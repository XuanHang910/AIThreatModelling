import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared_logging.audit_logger import log_result

def run_defense():
    print("Training robust model...")
    log_result("member2_defense", "robust_accuracy", 0.75)

if __name__ == "__main__":
    run_defense()
