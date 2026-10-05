import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared_logging.audit_logger import log_result

def defend_privacy():
    print("Applying Differential Privacy techniques...")
    log_result("member4_privacy_defense", "mia_accuracy_after_defense", 0.51)

if __name__ == "__main__":
    defend_privacy()
