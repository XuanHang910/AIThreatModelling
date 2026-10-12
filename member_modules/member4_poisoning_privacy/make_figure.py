"""
Thành viên 4 - Tạo Figure 2 và các bảng số liệu cho báo cáo từ kết quả thực nghiệm.

Đọc:  results/poisoning.json, results/sanitization.json, results/mia.json, results/privacy_defense.json
Ghi:  results/Figure2.png  và  results/tables.md
Chạy sau khi đã chạy đủ 4 script thực nghiệm.
"""
import os
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")

METHOD_NAME = {"unsupervised": "Không giám sát", "reference": "Có tập tham chiếu"}
METHOD_SHORT = {"unsupervised": "Không\ngiám sát", "reference": "Tham\nchiếu"}
VARIANT_NAME = {"none": "Không phòng thủ", "dropout": "Dropout + WD",
                "dp_sigma1.0": "DP-SGD σ=1", "dp_sigma2.0": "DP-SGD σ=2"}


def load(name):
    path = os.path.join(RES, name)
    if not os.path.exists(path):
        raise SystemExit(f"Thiếu {path}. Hãy chạy script tương ứng trước.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def make_figure(pois, san, priv):
    fig, axs = plt.subplots(2, 2, figsize=(14, 10), constrained_layout=True)
    fig.suptitle("Figure 2. Data Poisoning (Backdoor) và Membership Inference: tấn công và phòng thủ",
                 fontsize=14, fontweight="bold")

    # (a) ASR theo tỉ lệ nhiễm độc
    ax = axs[0, 0]
    colors = {"plain": "#7f7f7f", "adversarial": "#d62728"}
    labels = {"plain": "Chỉ gắn trigger (plain)", "adversarial": "Nhiễu đối kháng + trigger"}
    for mode in ["plain", "adversarial"]:
        rows = pois["results"][mode]
        x = [r["poison_rate"] * 100 for r in rows]
        y = [r["asr_mean"] * 100 for r in rows]
        e = [r["asr_std"] * 100 for r in rows]
        ax.errorbar(x, y, yerr=e, marker="o", capsize=4, color=colors[mode], label=labels[mode])
    ax.axhline(pois["baseline"]["asr_mean"] * 100, ls="--", color="#1f77b4",
               label="Mô hình sạch (ASR tự nhiên)")
    ax.set_xlabel("Tỉ lệ mẫu độc trong tập huấn luyện (%)")
    ax.set_ylabel("ASR (%)")
    ax.set_title("(a) Hiệu quả tấn công backdoor clean-label")
    ax.legend()
    ax.grid(alpha=0.3)

    # (b) Isolation Forest: tỉ lệ mẫu độc bị loại so với mẫu sạch bị loại nhầm
    ax = axs[0, 1]
    rows = san["rows"]
    names = [f"{METHOD_SHORT[r['method']]}\n{r['level']:.0%}" for r in rows]
    det = [r["detection_rate"] * 100 for r in rows]
    fpr = [r["false_positive_rate"] * 100 for r in rows]
    x = np.arange(len(rows))
    ax.bar(x - 0.2, det, 0.4, color="#2ca02c", label="Mẫu độc bị loại (phát hiện đúng)")
    ax.bar(x + 0.2, fpr, 0.4, color="#ff7f0e", label="Mẫu sạch bị loại nhầm")
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=9)
    ax.set_ylabel("%")
    ax.set_title(f"(b) Isolation Forest (nhiễm độc {san['poison_rate']:.0%}, {san['n_poison']} mẫu độc)")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)

    # (c) Độ chính xác MIA theo cấu hình phòng thủ
    ax = axs[1, 0]
    prow = priv["rows"]
    pn = [VARIANT_NAME.get(r["variant"], r["variant"]) for r in prow]
    mia = [r["mia_accuracy"] * 100 for r in prow]
    bars = ax.bar(pn, mia, color=["#d62728", "#ff7f0e", "#2ca02c", "#2ca02c"][:len(prow)])
    for b, v in zip(bars, mia):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.3, f"{v:.1f}%", ha="center", fontsize=9)
    ax.axhline(50, ls="--", color="black", label="Đoán mò (50%)")
    ax.set_ylim(40, max(mia) + 5)
    ax.set_ylabel("Độ chính xác MIA (%)  (trục bắt đầu từ 40%)")
    ax.set_title("(c) Rò rỉ quyền riêng tư (MIA) trước/sau phòng thủ")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    # (d) Đánh đổi riêng tư - hữu dụng
    ax = axs[1, 1]
    for r, n in zip(prow, pn):
        ax.scatter(r["test_acc"] * 100, r["mia_accuracy"] * 100, s=90)
        ax.annotate(n, (r["test_acc"] * 100, r["mia_accuracy"] * 100),
                    textcoords="offset points", xytext=(6, 6), fontsize=9)
    ax.axhline(50, ls="--", color="black")
    ax.set_xlabel("Độ chính xác trên tập kiểm thử (%)  →  hữu dụng hơn")
    ax.set_ylabel("Độ chính xác MIA (%)  ↓  riêng tư hơn")
    ax.set_title("(d) Đánh đổi giữa riêng tư và độ chính xác")
    ax.grid(alpha=0.3)

    out = os.path.join(RES, "Figure2.png")
    fig.savefig(out, dpi=200)
    plt.close(fig)
    return out


def make_tables(pois, san, mia, priv):
    L = []
    b = pois["baseline"]
    L.append(f"**Bảng 1. Tấn công backdoor clean-label** (dataset {pois['dataset']}, lớp mục tiêu "
             f"{pois['target_class']}, {pois['n_train']} mẫu huấn luyện, trung bình {len(pois['seeds'])} seed)\n")
    L.append(f"Mô hình sạch: độ chính xác {b['clean_accuracy_mean']*100:.2f}%, ASR tự nhiên của trigger "
             f"{b['asr_mean']*100:.2f}%.\n")
    L.append("| Tỉ lệ nhiễm độc | Số mẫu độc | ASR plain (%) | ASR adversarial (%) | Độ chính xác sạch adversarial (%) |")
    L.append("|---|---|---|---|---|")
    for rp, ra in zip(pois["results"]["plain"], pois["results"]["adversarial"]):
        L.append(f"| {ra['poison_rate']:.1%} | {ra['n_poison']} | {rp['asr_mean']*100:.2f} ± {rp['asr_std']*100:.2f} "
                 f"| {ra['asr_mean']*100:.2f} ± {ra['asr_std']*100:.2f} | {ra['clean_accuracy_mean']*100:.2f} |")
    L.append("")
    sb = san["baseline"]
    L.append(f"**Bảng 2. Làm sạch dữ liệu bằng Isolation Forest** (nhiễm độc {san['poison_rate']:.0%} = "
             f"{san['n_poison']} mẫu độc; trước khi lọc: ASR {sb['asr_before']*100:.2f}%, độ chính xác "
             f"{sb['clean_acc_before']*100:.2f}%)\n")
    L.append("| Cách | Mức | Số mẫu bị loại | Mẫu độc bị loại (%) | Mẫu sạch bị loại nhầm (%) | ASR sau lọc (%) | Độ chính xác sau lọc (%) |")
    L.append("|---|---|---|---|---|---|---|")
    for r in san["rows"]:
        L.append(f"| {METHOD_NAME[r['method']]} | {r['level']:.2f} | {r['n_removed']:.0f} | {r['detection_rate']*100:.1f} "
                 f"| {r['false_positive_rate']*100:.1f} | {r['asr_after']*100:.2f} | {r['clean_acc_after']*100:.2f} |")
    L.append("")
    m = mia["mean"]
    L.append(f"**Bảng 3. Membership Inference Attack và phòng thủ** ({mia['n_members']} mẫu huấn luyện, "
             f"{mia['epochs']} epoch, trung bình {len(mia['seeds'])} seed; 50% = đoán mò)\n")
    L.append("| Cấu hình | Độ chính xác MIA (%) | AUC | Độ chính xác huấn luyện (%) | Độ chính xác kiểm thử (%) |")
    L.append("|---|---|---|---|---|")
    for r in priv["rows"]:
        L.append(f"| {VARIANT_NAME.get(r['variant'], r['variant'])} | {r['mia_accuracy']*100:.1f} | {r['mia_auc']:.3f} "
                 f"| {r['train_acc']*100:.1f} | {r['test_acc']*100:.1f} |")
    L.append("")
    L.append("Ghi chú: DP-SGD là bản tự cài đặt (cắt gradient từng mẫu + nhiễu Gaussian), không tính ngân sách epsilon chính thức.")
    out = os.path.join(RES, "tables.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    return out, "\n".join(L)


if __name__ == "__main__":
    pois, san = load("poisoning.json"), load("sanitization.json")
    mia, priv = load("mia.json"), load("privacy_defense.json")
    fig_path = make_figure(pois, san, priv)
    tab_path, text = make_tables(pois, san, mia, priv)
    print(text)
    print(f"\nĐã tạo: {fig_path}\nĐã tạo: {tab_path}")