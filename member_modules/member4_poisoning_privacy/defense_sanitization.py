"""
Thành viên 4 - Phòng thủ: làm sạch dữ liệu huấn luyện bằng Isolation Forest.

Hai cách dùng Isolation Forest (so sánh trong báo cáo):
  A) "unsupervised": chạy Isolation Forest trên đặc trưng của CHÍNH tập huấn luyện, từng lớp một.
     Chỉ hiệu quả khi mẫu độc là thiểu số hiếm trong lớp.
  B) "reference"   : fit Isolation Forest trên một tập SẠCH đáng tin cậy nhỏ (N_TRUSTED mẫu), rồi chấm điểm
     tập huấn luyện; mẫu có điểm thấp hơn ngưỡng (hiệu chỉnh trên phần sạch giữ riêng) bị loại.

Quy trình mỗi seed: tạo tập độc -> huấn luyện mô hình nhiễm độc -> lấy đặc trưng lớp ẩn fc1 (50 chiều)
-> phát hiện -> loại mẫu -> huấn luyện lại -> đo ASR và độ chính xác.
Chỉ số: tỉ lệ mẫu độc bị loại (detection), tỉ lệ mẫu sạch bị loại nhầm (false positive), ASR trước/sau.
"""
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import torch
from sklearn.ensemble import IsolationForest
from m4_common import (SimpleCNN, load_data, load_trusted_clean, make_poisoned_train, train_model,
                       accuracy, attack_success_rate, penultimate_features, save_json, log_result,
                       TARGET_CLASS, N_TRAIN, N_TEST, EPOCHS, SEEDS, HEADLINE_RATE, HEADLINE_MODE)

LEVELS = [0.05, 0.10, 0.20]        # contamination (cách A) / phân vị ngưỡng trên tập sạch (cách B)
METHODS = ["unsupervised", "reference"]
N_TRUSTED = 2000                   # kích thước tập sạch đáng tin cậy cho cách B
HEADLINE_METHOD = "reference"
HEADLINE_LEVEL = 0.10


def detect(method, level, feats, y_np, feats_trust, ytrust_np, seed):
    flagged = np.zeros(len(y_np), dtype=bool)
    for c in range(10):
        idx = np.where(y_np == c)[0]
        if method == "unsupervised":
            iso = IsolationForest(n_estimators=200, contamination=level, random_state=seed)
            pred = iso.fit_predict(feats[idx])
            flagged[idx[pred == -1]] = True
        else:
            tidx = np.where(ytrust_np == c)[0]
            half = len(tidx) // 2
            iso = IsolationForest(n_estimators=200, random_state=seed).fit(feats_trust[tidx[:half]])
            thr = np.percentile(iso.score_samples(feats_trust[tidx[half:]]), 100 * level)
            flagged[idx[iso.score_samples(feats[idx]) < thr]] = True
    return flagged


def defense_sanitization():
    print("Running Isolation Forest sanitization...")
    Xtr, ytr, Xte, yte, dataset = load_data(N_TRAIN, N_TEST, seed=0)
    Xtrust, ytrust = load_trusted_clean(N_TRUSTED, seed=0)
    ytrust_np = ytrust.numpy()
    print(f"Dataset: {dataset} | kiểu mẫu độc={HEADLINE_MODE} | tỉ lệ nhiễm độc={HEADLINE_RATE:.1%} "
          f"| tập sạch tin cậy={len(Xtrust)} mẫu")

    keys = [(m, l) for m in METHODS for l in LEVELS]
    stats = {k: {"det": [], "fpr": [], "prec": [], "removed": [], "asr": [], "acc": []} for k in keys}
    asr_before, acc_before = [], []
    n_poison = 0

    for seed in SEEDS:
        surrogate = None
        if HEADLINE_MODE == "adversarial":
            surrogate = train_model(SimpleCNN(), Xtr, ytr, epochs=EPOCHS, seed=seed + 100)
        Xp, yp, mask = make_poisoned_train(Xtr, ytr, HEADLINE_RATE, seed=seed,
                                           mode=HEADLINE_MODE, surrogate=surrogate)
        mask_np = mask.numpy()
        n_poison = int(mask_np.sum())

        poisoned_model = train_model(SimpleCNN(), Xp, yp, epochs=EPOCHS, seed=seed)
        asr_before.append(attack_success_rate(poisoned_model, Xte, yte))
        acc_before.append(accuracy(poisoned_model, Xte, yte))
        feats = penultimate_features(poisoned_model, Xp)
        feats_trust = penultimate_features(poisoned_model, Xtrust)
        y_np = yp.numpy()

        for (method, level) in keys:
            flagged = detect(method, level, feats, y_np, feats_trust, ytrust_np, seed)
            tp = int((flagged & mask_np).sum())
            s = stats[(method, level)]
            s["det"].append(tp / max(n_poison, 1))
            s["fpr"].append(int((flagged & ~mask_np).sum()) / max(int((~mask_np).sum()), 1))
            s["prec"].append(tp / max(int(flagged.sum()), 1))
            s["removed"].append(int(flagged.sum()))
            keep = torch.tensor(~flagged)
            cleaned = train_model(SimpleCNN(), Xp[keep], yp[keep], epochs=EPOCHS, seed=seed)
            s["asr"].append(attack_success_rate(cleaned, Xte, yte))
            s["acc"].append(accuracy(cleaned, Xte, yte))
        print(f"  seed {seed} xong")

    base = {"asr_before": float(np.mean(asr_before)), "clean_acc_before": float(np.mean(acc_before))}
    print(f"  [trước khi lọc] n_mẫu_độc={n_poison} | ASR={base['asr_before']:.4f} "
          f"| clean_acc={base['clean_acc_before']:.4f}")

    rows = []
    for (method, level) in keys:
        s = stats[(method, level)]
        row = {"method": method, "level": level, "n_removed": float(np.mean(s["removed"])),
               "detection_rate": float(np.mean(s["det"])), "false_positive_rate": float(np.mean(s["fpr"])),
               "precision": float(np.mean(s["prec"])), "asr_after": float(np.mean(s["asr"])),
               "clean_acc_after": float(np.mean(s["acc"]))}
        rows.append(row)
        print(f"  [{method:<12}] level={level:.2f} | loại ~{row['n_removed']:.0f} | "
              f"độc bị loại={row['detection_rate']:.3f} | sạch bị loại nhầm={row['false_positive_rate']:.3f} "
              f"| ASR sau lọc={row['asr_after']:.4f} | clean_acc={row['clean_acc_after']:.4f}")

    save_json("sanitization.json", {
        "dataset": dataset, "mode": HEADLINE_MODE, "poison_rate": HEADLINE_RATE, "n_poison": n_poison,
        "n_trusted": len(Xtrust), "target_class": TARGET_CLASS, "seeds": SEEDS, "baseline": base,
        "headline_method": HEADLINE_METHOD, "headline_level": HEADLINE_LEVEL, "rows": rows,
    })

    head = next(r for r in rows if r["method"] == HEADLINE_METHOD and r["level"] == HEADLINE_LEVEL)
    details = {"dataset": dataset, "mode": HEADLINE_MODE, "poison_rate": HEADLINE_RATE,
               "method": HEADLINE_METHOD, "level": HEADLINE_LEVEL,
               "false_positive_rate": head["false_positive_rate"], "asr_before": base["asr_before"],
               "asr_after": head["asr_after"], "clean_acc_after": head["clean_acc_after"]}
    log_result("member4_sanitization", "malicious_samples_removed",
               round(head["detection_rate"], 4), details)


if __name__ == "__main__":
    defense_sanitization()