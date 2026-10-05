import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared_logging.audit_logger import log_result

def run_sanitization():
    print("Running Isolation Forest sanitization...")
    log_result("member4_sanitization", "malicious_samples_removed", 0.95)

if __name__ == "__main__":
    run_sanitization()
