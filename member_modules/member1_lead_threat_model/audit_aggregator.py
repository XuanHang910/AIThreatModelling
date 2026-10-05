import json
import os

def aggregate_and_report():
    log_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../shared_logging/audit_results.json"))
    if not os.path.exists(log_file):
        print("No audit logs found.")
        return
        
    with open(log_file, "r") as f:
        logs = json.load(f)
        
    print("Aggregating results...")
    for log in logs:
        print(f" - {log['module']} | {log['metric']}: {log['value']}")
        
    # Generate dummy report
    report_path = os.path.join(os.path.dirname(__file__), "AuditReport.md")
    with open(report_path, "w") as f:
        f.write("# Security Audit Report\n")
        f.write("Generated from automated checks.\n")
    print(f"Report written to {report_path}")

if __name__ == "__main__":
    aggregate_and_report()
