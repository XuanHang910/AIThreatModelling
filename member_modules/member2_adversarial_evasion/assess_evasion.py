import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared_logging.audit_logger import log_result

def run_evasion_test():
    print("Running FGSM/PGD evasion test...")
    # Dummy results
    epsilons = [0.1, 0.2, 0.3]
    accuracies = [0.8, 0.5, 0.2]
    
    for eps, acc in zip(epsilons, accuracies):
        log_result("member2_evasion", f"accuracy_eps_{eps}", acc)

if __name__ == "__main__":
    run_evasion_test()
