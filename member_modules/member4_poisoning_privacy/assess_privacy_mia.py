"""
Thành viên 4 - Thực nghiệm tấn công suy diễn thành viên (Membership Inference Attack - MIA).

Ý tưởng: mô hình thường cho loss rất thấp trên dữ liệu nó đã học (thành viên) và loss cao hơn trên dữ liệu
chưa thấy. Kẻ tấn công chỉ cần hỏi mô hình và so loss với một ngưỡng để đoán "mẫu này có trong tập huấn luyện không".
Đánh giá trên tập cân bằng (50% thành viên, 50% không) => đoán mò = 50%.
Ghi results/mia.json và shared_logging/audit_results.json.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from m4_common import (load_data, run_mia_trial, mean_over, save_json, log_result, N_TRAIN, N_TEST,
                       MIA_N_MEMBERS, MIA_EPOCHS, MIA_SEEDS)


def assess_privacy_mia():
    print("Testing Membership Inference Attack (MIA)...")
    Xtr, ytr, Xte, yte, dataset = load_data(N_TRAIN, N_TEST, seed=0)
    print(f"Dataset: {dataset} | thành viên={MIA_N_MEMBERS} | epochs={MIA_EPOCHS} | seeds={MIA_SEEDS}")

    trials = []
    for seed in MIA_SEEDS:
        r = run_mia_trial(Xtr, ytr, Xte, yte, seed, defense="none")
        trials.append(r)
        print(f"  seed {seed}: MIA acc={r['mia_accuracy']:.3f} | AUC={r['mia_auc']:.3f} | "
              f"train_acc={r['train_acc']:.3f} | test_acc={r['test_acc']:.3f}")

    mean = {k: mean_over(trials, k) for k in ["mia_accuracy", "mia_auc", "train_acc", "test_acc"]}
    print(f"  TRUNG BÌNH: MIA acc={mean['mia_accuracy']:.4f} | AUC={mean['mia_auc']:.4f} | "
          f"train_acc={mean['train_acc']:.4f} | test_acc={mean['test_acc']:.4f}")

    save_json("mia.json", {"dataset": dataset, "n_members": MIA_N_MEMBERS, "epochs": MIA_EPOCHS,
                           "seeds": MIA_SEEDS, "mean": mean, "per_seed": trials})
    details = {"dataset": dataset, "n_members": MIA_N_MEMBERS, "epochs": MIA_EPOCHS,
               "mia_auc": mean["mia_auc"], "train_acc": mean["train_acc"], "test_acc": mean["test_acc"]}
    log_result("member4_privacy", "mia_accuracy", round(mean["mia_accuracy"], 4), details)


if __name__ == "__main__":
    assess_privacy_mia()