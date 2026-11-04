"""
Thành viên 4 - Giải quyết điểm nghẽn Backdoor: Activation Clustering và Spectral Signatures trên lớp fc1.

Câu hỏi cần trả lời: khi nhiễm độc 5% (mẫu độc chiếm khoảng một nửa lớp mục tiêu, nơi Isolation Forest bị vô hiệu hóa),
các kỹ thuật phát hiện dựa trên biểu diễn đặc trưng có lọc được mẫu backdoor hay không?

Quy trình mỗi seed: tạo tập độc 5% -> huấn luyện mô hình nhiễm độc -> lấy đặc trưng fc1 (50 chiều) ->
  (1) Activation Clustering: PCA(10) + k-means 2 cụm trong từng lớp; lớp nào có silhouette cao bất thường bị nghi ngờ,
      loại cụm nhỏ hơn (quy tắc gốc) -> "size". Biến thể "oracle" chọn đúng cụm nhờ nhãn thật = CẬN TRÊN (mô phỏng
      chuyên gia xem ảnh trung bình của cụm), không phải phòng thủ tự động.
  (2) Spectral Signatures: loại q% mẫu có điểm phổ cao nhất trong mỗi lớp.
-> huấn luyện lại -> đo ASR / độ chính xác. Có thêm đối chứng: loại NGẪU NHIÊN cùng số lượng mẫu.
Ghi results/activation_defense.json và shared_logging/audit_results.json.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import torch
from m4_common import (SimpleCNN, load_data, make_poisoned_train, train_model, accuracy,
                       attack_success_rate, penultimate_features, save_json, log_result,
                       TARGET_CLASS, N_TRAIN, N_TEST, EPOCHS, SEEDS, HEADLINE_MODE)
from m4_detect import activation_clustering, spectral_signatures, class_diagnostics

ATTACK_RATE = 0.05               # nhiễm độc 5%, nơi Isolation Forest bị vô hiệu hóa
SS_LEVELS = [0.10, 0.20, 0.30]   # tỉ lệ mẫu bị loại trong MỖI lớp (Spectral Signatures)
HEADLINE_SS = "spectral_0.30"

NAMES = {"activation_clustering_size": "Activation Clustering (loại cụm nhỏ)",
         "activation_clustering_oracle": "Activation Clustering (chọn đúng cụm, cận trên)"}
for _q in SS_LEVELS:
    NAMES[f"spectral_{_q:.2f}"] = f"Spectral Signatures (loại {_q:.0%}/lớp)"


def evaluate(flagged, mask_np, Xp, yp, Xte, yte, seed, base_asr, base_acc):
    n_removed = int(flagged.sum())
    tp = int((flagged & mask_np).sum())
    res = {"n_removed": n_removed,
           "det": tp / max(int(mask_np.sum()), 1),
           "fpr": int((flagged & ~mask_np).sum()) / max(int((~mask_np).sum()), 1),
           "prec": tp / max(n_removed, 1)}
    if n_removed == 0:  # không loại gì => mô hình giữ nguyên
        res.update(asr=base_asr, acc=base_acc, asr_ctrl=base_asr)
        return res
    keep = torch.tensor(~flagged)
    model = train_model(SimpleCNN(), Xp[keep], yp[keep], epochs=EPOCHS, seed=seed)
    res["asr"] = attack_success_rate(model, Xte, yte)
    res["acc"] = accuracy(model, Xte, yte)
    # đối chứng: loại ngẫu nhiên cùng số lượng
    rng = np.random.RandomState(seed + 7)
    rand_flag = np.zeros(len(flagged), dtype=bool)
    rand_flag[rng.choice(len(flagged), n_removed, replace=False)] = True
    keep_r = torch.tensor(~rand_flag)
    model_r = train_model(SimpleCNN(), Xp[keep_r], yp[keep_r], epochs=EPOCHS, seed=seed)
    res["asr_ctrl"] = attack_success_rate(model_r, Xte, yte)
    return res


def defense_activation():
    print("Running activation-based backdoor detection (Activation Clustering / Spectral Signatures)...")
    Xtr, ytr, Xte, yte, dataset = load_data(N_TRAIN, N_TEST, seed=0)
    print(f"Dataset: {dataset} | kiểu mẫu độc={HEADLINE_MODE} | tỉ lệ nhiễm độc={ATTACK_RATE:.1%} | seeds={SEEDS}")

    stats = {m: [] for m in NAMES}
    diags, ac_classes, asr_b_list, acc_b_list = [], [], [], []
    n_poison = 0

    for seed in SEEDS:
        surrogate = None
        if HEADLINE_MODE == "adversarial":
            surrogate = train_model(SimpleCNN(), Xtr, ytr, epochs=EPOCHS, seed=seed + 100)
        Xp, yp, mask = make_poisoned_train(Xtr, ytr, ATTACK_RATE, seed=seed,
                                           mode=HEADLINE_MODE, surrogate=surrogate)
        mask_np = mask.numpy()
        y_np = yp.numpy()
        n_poison = int(mask_np.sum())

        poisoned_model = train_model(SimpleCNN(), Xp, yp, epochs=EPOCHS, seed=seed)
        asr_b = attack_success_rate(poisoned_model, Xte, yte)
        acc_b = accuracy(poisoned_model, Xte, yte)
        asr_b_list.append(asr_b)
        acc_b_list.append(acc_b)
        feats = penultimate_features(poisoned_model, Xp)

        f_size, f_oracle, info = activation_clustering(feats, y_np, seed=seed, is_poison=mask_np)
        diags.append(class_diagnostics(feats, y_np, mask_np, TARGET_CLASS, info, seed=seed))
        ac_classes.append(info["flagged_classes"])

        flags = {"activation_clustering_size": f_size, "activation_clustering_oracle": f_oracle}
        for q in SS_LEVELS:
            flags[f"spectral_{q:.2f}"] = spectral_signatures(feats, y_np, q)
        for name, flagged in flags.items():
            stats[name].append(evaluate(flagged, mask_np, Xp, yp, Xte, yte, seed, asr_b, acc_b))
        print(f"  seed {seed} xong | lớp bị Activation Clustering nghi ngờ: {info['flagged_classes']}")

    base = {"asr_before": float(np.mean(asr_b_list)), "clean_acc_before": float(np.mean(acc_b_list))}
    print(f"\n[trước khi lọc] n_mẫu_độc={n_poison} | ASR={base['asr_before']:.4f} | clean_acc={base['clean_acc_before']:.4f}")

    def dmean(key):
        vals = [d[key] for d in diags if key in d]
        return float(np.mean(vals)) if vals else None

    pf = [sorted(d["poison_frac_in_clusters"]) for d in diags if "poison_frac_in_clusters" in d]
    diag = {k: dmean(k) for k in ["poison_frac_in_class", "auc_isolation_forest", "auc_spectral", "ari",
                                   "silhouette_target", "silhouette_median_others"]}
    diag["poison_frac_cluster_low"] = float(np.mean([p[0] for p in pf])) if pf else None
    diag["poison_frac_cluster_high"] = float(np.mean([p[1] for p in pf])) if pf else None
    print(f"[chẩn đoán lớp {TARGET_CLASS}] mẫu độc chiếm {diag['poison_frac_in_class']:.1%} lớp | "
          f"AUROC điểm bất thường: IsolationForest={diag['auc_isolation_forest']:.3f}, "
          f"SpectralSignatures={diag['auc_spectral']:.3f} (0.5 = vô dụng)")
    print(f"                   k-means 2 cụm: ARI={diag['ari']:.3f} | tỉ lệ mẫu độc trong 2 cụm="
          f"{diag['poison_frac_cluster_low']:.2f} và {diag['poison_frac_cluster_high']:.2f} | "
          f"silhouette lớp {TARGET_CLASS}={diag['silhouette_target']:.3f} (trung vị các lớp khác={diag['silhouette_median_others']:.3f})")
    print(f"                   lớp bị nghi ngờ theo từng seed: {ac_classes}\n")

    rows = []
    for name in NAMES:
        s = stats[name]
        row = {"method": name, "label": NAMES[name]}
        for k_out, k_in in [("n_removed", "n_removed"), ("detection_rate", "det"), ("false_positive_rate", "fpr"),
                            ("precision", "prec"), ("asr_after", "asr"), ("asr_random_control", "asr_ctrl"),
                            ("clean_acc_after", "acc")]:
            row[k_out] = float(np.mean([r[k_in] for r in s]))
        rows.append(row)
        print(f"  [{NAMES[name]}] loại ~{row['n_removed']:.0f} | độc bị loại={row['detection_rate']:.3f} | "
              f"sạch bị loại nhầm={row['false_positive_rate']:.3f} | ASR sau lọc={row['asr_after']:.4f} "
              f"(đối chứng loại ngẫu nhiên: {row['asr_random_control']:.4f}) | clean_acc={row['clean_acc_after']:.4f}")

    save_json("activation_defense.json", {
        "dataset": dataset, "mode": HEADLINE_MODE, "poison_rate": ATTACK_RATE, "n_poison": n_poison,
        "target_class": TARGET_CLASS, "seeds": SEEDS, "baseline": base, "diagnostics_target_class": diag,
        "activation_clustering_flagged_classes_per_seed": ac_classes, "rows": rows})

    r_ac = next(r for r in rows if r["method"] == "activation_clustering_size")
    r_or = next(r for r in rows if r["method"] == "activation_clustering_oracle")
    r_ss = next(r for r in rows if r["method"] == HEADLINE_SS)
    common = {"dataset": dataset, "mode": HEADLINE_MODE, "poison_rate": ATTACK_RATE, "n_poison": n_poison,
              "asr_before": base["asr_before"]}
    log_result("member4_activation_clustering", "malicious_samples_removed", round(r_ac["detection_rate"], 4),
               {**common, "rule": "smaller cluster", "false_positive_rate": r_ac["false_positive_rate"],
                "asr_after": r_ac["asr_after"], "detection_rate_oracle_cluster": r_or["detection_rate"],
                "ari_target_class": diag["ari"]})
    log_result("member4_spectral_signatures", "malicious_samples_removed", round(r_ss["detection_rate"], 4),
               {**common, "level": HEADLINE_SS, "false_positive_rate": r_ss["false_positive_rate"],
                "asr_after": r_ss["asr_after"], "auc_target_class": diag["auc_spectral"]})


if __name__ == "__main__":
    defense_activation()