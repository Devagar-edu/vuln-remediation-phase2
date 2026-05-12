import json
from jira import JIRA
import sys
import os

PROJECT_KEY = "SCRUM"

BASE_DIR = os.getcwd()

def safe_path(user_input):
    """Allow only filenames, force them into BASE_DIR to prevent traversal"""
    filename = os.path.basename(user_input)
    return os.path.join(BASE_DIR, filename)



def connect_jira():
       
                                                
    
                                                                     
       
                                                         
    
                                                                        
                               
                                                 
    
                                                                             
    return JIRA(
        server=os.environ.get('JIRA_URL'),
        basic_auth=(os.environ.get("JIRA_EMAIL"), os.environ.get("JIRA_API_TOKEN"))
                                         
    )


def load_scan(json_file):
       
                                     
    
                                                                   
    
            
                                       
       
    with open(json_file) as f:
        return json.load(f)


def build_summary(scan):

                                       
    
                                                                   
    
               
                                                                                                                          
                                                                                  
    
               
                                                                       
                                                                 
    
         
                                                
    
            
                                                            
       
    dep_count = len(scan.get("dependency_vulnerabilities", []))
    code_count = len(scan.get("code_vulnerabilities", []))
    
                                                                           
                         
                                                    
                                                                         
                                                                       
                                
    
                     
                                                              
                                  
                                    
         
                                                                 
                                                                                                      
                                                                                                                            

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

                                                  
    
                                                                   
                                                         
    
         
                                                            
       
    jira = connect_jira()
    scan = load_scan(json_file)

    description = build_summary(scan)
    
                                    
                                                          
    
                                   
                                      
    
                                 
                                 
                             
                                      
                                  
                            

    issue_dict = {
        "project": {"key": PROJECT_KEY},
        "summary": f"Security Scan Findings - {scan['scan_metadata']['project']}",
        "description": description,
        "issuetype": {"name": "Task"},
        "labels": ["security", "snyk", "auto-scan"]
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

    # Validate file exists
    if not os.path.isfile(json_file):
        print(f"File not found: {json_file}")
        sys.exit(1)

    create_jira_ticket(json_file)
