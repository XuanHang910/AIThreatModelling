"""
Thành viên 4 - Thực nghiệm tấn công đầu độc dữ liệu (clean-label backdoor).

Làm gì:
  1. Huấn luyện mô hình sạch để lấy mốc (độ chính xác, ASR tự nhiên của trigger).
  2. Với từng tỉ lệ nhiễm độc, tạo mẫu độc theo 2 kiểu (nhãn luôn được giữ nguyên):
       - "plain"       : chỉ gắn trigger vào ảnh lớp mục tiêu
       - "adversarial" : làm nhiễu đối kháng (PGD) rồi mới gắn trigger
  3. Đo độ chính xác trên ảnh sạch (độ suy giảm) và ASR trên ảnh có trigger.
  4. Ghi results/poisoning.json và shared_logging/audit_results.json.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import numpy as np
from m4_common import (SimpleCNN, load_data, make_poisoned_train, train_model, accuracy,
                       attack_success_rate, save_json, log_result, TARGET_CLASS, N_TRAIN, N_TEST,
                       EPOCHS, SEEDS, POISON_RATES, HEADLINE_RATE, HEADLINE_MODE, PGD_EPS, PGD_STEPS)

MODES = ["plain", "adversarial"]


def summarize(accs, asrs):
    return {"clean_accuracy_mean": float(np.mean(accs)), "clean_accuracy_std": float(np.std(accs)),
            "asr_mean": float(np.mean(asrs)), "asr_std": float(np.std(asrs))}


def assess_poisoning():
    print("Testing clean-label backdoor...")
    Xtr, ytr, Xte, yte, dataset = load_data(N_TRAIN, N_TEST, seed=0)
    print(f"Dataset: {dataset} | train={len(Xtr)} | test={len(Xte)} | lớp mục tiêu={TARGET_CLASS}")

    # --- Mô hình sạch (mốc so sánh) + mô hình thay thế cho kẻ tấn công ---
    accs, asrs, surrogates = [], [], {}
    for seed in SEEDS:
        clean = train_model(SimpleCNN(), Xtr, ytr, epochs=EPOCHS, seed=seed)
        accs.append(accuracy(clean, Xte, yte))
        asrs.append(attack_success_rate(clean, Xte, yte))
        surrogates[seed] = train_model(SimpleCNN(), Xtr, ytr, epochs=EPOCHS, seed=seed + 100)
    baseline = summarize(accs, asrs)
    print(f"  [mô hình sạch] clean_acc={baseline['clean_accuracy_mean']:.4f} | "
          f"ASR tự nhiên của trigger={baseline['asr_mean']:.4f}")

    # --- Tấn công ---
    results = {m: [] for m in MODES}
    for mode in MODES:
        print(f"  --- kiểu mẫu độc: {mode} ---")
        for rate in POISON_RATES:
            accs, asrs, n_poison = [], [], 0
            for seed in SEEDS:
                Xp, yp, mask = make_poisoned_train(Xtr, ytr, rate, seed=seed, mode=mode,
                                                   surrogate=surrogates[seed])
                n_poison = int(mask.sum())
                model = train_model(SimpleCNN(), Xp, yp, epochs=EPOCHS, seed=seed)
                accs.append(accuracy(model, Xte, yte))
                asrs.append(attack_success_rate(model, Xte, yte))
            row = {"poison_rate": rate, "n_poison": n_poison, **summarize(accs, asrs)}
            results[mode].append(row)
            print(f"    poison_rate={rate:>5.1%} (n={n_poison:>4}) | "
                  f"clean_acc={row['clean_accuracy_mean']:.4f} | "
                  f"ASR={row['asr_mean']:.4f} (±{row['asr_std']:.4f})")

    headline = next(r for r in results[HEADLINE_MODE] if r["poison_rate"] == HEADLINE_RATE)
    drop = baseline["clean_accuracy_mean"] - headline["clean_accuracy_mean"]

    save_json("poisoning.json", {
        "dataset": dataset, "target_class": TARGET_CLASS, "n_train": len(Xtr), "n_test": len(Xte),
        "epochs": EPOCHS, "seeds": SEEDS, "pgd_eps": PGD_EPS, "pgd_steps": PGD_STEPS,
        "headline_rate": HEADLINE_RATE, "headline_mode": HEADLINE_MODE,
        "baseline": baseline, "clean_accuracy_drop": drop, "results": results,
    })

    details = {"dataset": dataset, "mode": HEADLINE_MODE, "poison_rate": HEADLINE_RATE,
               "n_poison": headline["n_poison"], "target_class": TARGET_CLASS,
               "clean_accuracy": headline["clean_accuracy_mean"],
               "clean_accuracy_baseline": baseline["clean_accuracy_mean"],
               "baseline_asr_no_poison": baseline["asr_mean"]}
    log_result("member4_poisoning", "attack_success_rate", round(headline["asr_mean"], 4), details)
    log_result("member4_poisoning", "clean_accuracy_drop", round(drop, 4), details)


if __name__ == "__main__":
    assess_poisoning()