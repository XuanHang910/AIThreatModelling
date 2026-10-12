"""Red Team - tấn công né tránh (FGSM / PGD, IBM ART) lên target_systems/classifier."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c 
import torch  


def run_evasion_test():
    print("Running FGSM/PGD evasion test...")
    c.set_seed()
    x_tr, y_tr, x_te, y_te, dataset = c.load_data()
    print(f"Dataset: {dataset} | train={len(x_tr)} test={len(x_te)}")

    # Mô hình mục tiêu (kiến trúc SimpleCNN của target_systems/classifier).
    model = c.train_model(c.SimpleCNN(), x_tr, y_tr)
    torch.save(model.state_dict(), os.path.join(c.HERE, "evasion_clean_model.pth"))

    clf = c.make_classifier(model)
    clean_acc = c.accuracy(model, x_te, y_te)
    print(f"Clean accuracy: {clean_acc:.4f}")

    results = {"dataset": dataset, "n_test": len(x_te), "clean_accuracy": clean_acc,
               "fgsm": {}, "pgd": {}, "max_linf": {"fgsm": {}, "pgd": {}}}
    c.reset_logs("member2_evasion", "member2_defense")
    c.log_result("member2_evasion", "clean_accuracy", clean_acc, {"dataset": dataset})

    for kind in ("fgsm", "pgd"):
        for eps in c.EPSILONS:
            acc, linf = c.accuracy_under_attack(clf, x_te, y_te, kind, eps)
            results[kind][str(eps)] = acc
            results["max_linf"][kind][str(eps)] = linf
            c.log_result("member2_evasion", f"accuracy_{kind}_eps_{eps}", acc,
                         {"dataset": dataset, "max_linf": round(linf, 4)})

    path = c.save_json("evasion_results.json", results)
    print(f"Saved: {path}")


if __name__ == "__main__":
    run_evasion_test()
