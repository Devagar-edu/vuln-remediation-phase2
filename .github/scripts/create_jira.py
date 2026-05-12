import json
from jira import JIRA
import sys
import os

PROJECT_KEY = "SCRUM"
BASE_DIR = os.getcwd()


def safe_path(user_input):
    """Prevent path traversal and keep file inside working directory"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)


def to_adf(text: str):
    """
    Convert plain text into Atlassian Document Format (ADF)
    required by Jira Cloud API v3 for description field.
    """
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": text
                    }
                ]
            }
        ]
    }


def connect_jira():
    """
    Connect to Jira Cloud using API v3.
    """
    jira_url = os.environ.get('JIRA_URL', '').rstrip('/')

    # Remove accidental REST path if present
    if '/rest/api' in jira_url:
        jira_url = jira_url.split('/rest/api')[0]

    return JIRA(
        server=jira_url,
        basic_auth=(
            os.environ.get("JIRA_EMAIL"),
            os.environ.get("JIRA_API_TOKEN")
        ),
        options={'rest_api_version': '3'}
    )


def load_scan(json_file):
    """Load scan results JSON"""
    with open(json_file) as f:
        return json.load(f)


def build_summary(scan):
    """Build Jira issue description text"""
    dep_vulns = scan.get("dependency_vulnerabilities", [])
    code_vulns = scan.get("code_vulnerabilities", [])

    is_new_format = False
    if dep_vulns and isinstance(dep_vulns[0], dict):
        if "package_name" in dep_vulns[0] or "scanner" in dep_vulns[0]:
            is_new_format = True

    if is_new_format:
        dep_count = len(dep_vulns)
        code_count = len(code_vulns)
    else:
        dep_count = sum(len(d.get("vulnerabilities", [])) for d in dep_vulns)
        code_count = len(code_vulns)

    summary = f"""
Security Scan Report

Project: {scan['scan_metadata']['project']}
Repository: {scan['scan_metadata']['repository']}
Branch: {scan['scan_metadata']['branch']}
Scanner: {scan['scan_metadata']['scanner']}

Summary
-------
Dependency vulnerabilities detected: {dep_count}
Code vulnerabilities detected: {code_count}

Full vulnerability details are attached in scan_payload.json.
AI remediation planner will analyze the attachment and suggest fixes.
"""

    return summary.strip()


def create_jira_ticket(json_file):
    """Create Jira ticket and attach scan report"""

    jira = connect_jira()
    scan = load_scan(json_file)

    description_text = build_summary(scan)

    scanner = scan['scan_metadata'].get('scanner', 'snyk')

    labels = ["security", "auto-scan"]

    if "snyk" in scanner.lower():
        labels.append("snyk")
    if "inspector" in scanner.lower():
        labels.append("inspector")
        labels.append("aws")

    issue_dict = {
        "project": {"key": PROJECT_KEY},
        "summary": f"Security Scan Findings ({scanner}) - {scan['scan_metadata']['project']}",
        "description": to_adf(description_text),   # ✅ FIXED (ADF REQUIRED)
        "issuetype": {"name": "Task"},
        "labels": labels
    }

    issue = jira.create_issue(fields=issue_dict)

    print("Jira ticket created:", issue.key)

    with open(json_file, "rb") as f:
        jira.add_attachment(
            issue=issue.key,
            attachment=f,
            filename="scan_payload.json"
        )

    print("JSON attached to ticket.")


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python create_jira_issues.py <normalized_json>")
        sys.exit(1)

    json_file = safe_path(sys.argv[1])

    if not os.path.isfile(json_file):
        print(f"File not found: {json_file}")
        sys.exit(1)

    create_jira_ticket(json_file)
