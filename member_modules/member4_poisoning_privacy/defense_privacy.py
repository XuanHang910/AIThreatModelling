"""
Thành viên 4 - Phòng thủ quyền riêng tư trước MIA.

So sánh 3 cấu hình (cùng dữ liệu, cùng số epoch):
  - none      : mô hình không phòng thủ (mốc so sánh)
  - dropout   : Dropout(0.5) + weight decay (regularization, giảm ghi nhớ)
  - dp_sigma* : huấn luyện kiểu DP-SGD (cắt gradient từng mẫu + nhiễu Gaussian), sigma = noise multiplier
Đo: độ chính xác MIA (50% = đoán mò), AUC, và độ chính xác kiểm thử (đánh đổi giữa riêng tư và hữu dụng).
Lưu ý: DP-SGD tự cài đặt, KHÔNG tính ngân sách epsilon chính thức (muốn có epsilon dùng thư viện Opacus).
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from m4_common import (load_data, run_mia_trial, mean_over, save_json, log_result, N_TRAIN, N_TEST,
                       MIA_N_MEMBERS, MIA_EPOCHS, MIA_SEEDS)

VARIANTS = [
    ("none", {"defense": "none"}),
    ("dropout", {"defense": "dropout", "dropout_p": 0.5, "weight_decay": 5e-3}),
    ("dp_sigma1.0", {"defense": "dp", "sigma": 1.0, "clip_norm": 1.0}),
    ("dp_sigma2.0", {"defense": "dp", "sigma": 2.0, "clip_norm": 1.0}),
]
HEADLINE_VARIANT = "dp_sigma1.0"   # cấu hình dùng làm số liệu chính ghi vào audit_results.json


def defense_privacy():
    print("Applying Differential Privacy techniques...")
    Xtr, ytr, Xte, yte, dataset = load_data(N_TRAIN, N_TEST, seed=0)
    print(f"Dataset: {dataset} | thành viên={MIA_N_MEMBERS} | epochs={MIA_EPOCHS} | seeds={MIA_SEEDS}")

    rows = []
    for name, kwargs in VARIANTS:
        trials = [run_mia_trial(Xtr, ytr, Xte, yte, seed, **kwargs) for seed in MIA_SEEDS]
        row = {"variant": name, "config": kwargs}
        for k in ["mia_accuracy", "mia_auc", "train_acc", "test_acc"]:
            row[k] = mean_over(trials, k)
        rows.append(row)
        print(f"  [{name:<12}] MIA acc={row['mia_accuracy']:.4f} | AUC={row['mia_auc']:.4f} | "
              f"train_acc={row['train_acc']:.4f} | test_acc={row['test_acc']:.4f}")

    save_json("privacy_defense.json", {"dataset": dataset, "n_members": MIA_N_MEMBERS, "epochs": MIA_EPOCHS,
                                       "seeds": MIA_SEEDS, "headline_variant": HEADLINE_VARIANT, "rows": rows})
    head = next(r for r in rows if r["variant"] == HEADLINE_VARIANT)
    base = next(r for r in rows if r["variant"] == "none")
    details = {"dataset": dataset, "defense": HEADLINE_VARIANT, "mia_accuracy_no_defense": base["mia_accuracy"],
               "mia_auc": head["mia_auc"], "test_acc": head["test_acc"], "test_acc_no_defense": base["test_acc"],
               "all_variants": {r["variant"]: round(r["mia_accuracy"], 4) for r in rows}}
    log_result("member4_privacy_defense", "mia_accuracy_after_defense", round(head["mia_accuracy"], 4), details)


if __name__ == "__main__":
    defense_privacy()