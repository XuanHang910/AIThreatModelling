import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  


def pct(v):
    return f"{v:.1%}"


def main():
    b = c.load_json("evasion_results.json")
    a = c.load_json("defense_results.json")
    try:
        advanced = c.load_json("cw_vs_pgd_results.json")
    except FileNotFoundError:
        advanced = None
    eps_list = c.EPSILONS
    lo, hi = str(eps_list[0]), str(c.HEADLINE_EPS)

    rows = []
    for kind in ("fgsm", "pgd"):
        for e in eps_list:
            bb, aa = b[kind][str(e)], a[kind][str(e)]
            rows.append(f"| {kind.upper()} | {e} | {pct(bb)} | {pct(aa)} | {100 * (aa - bb):+.1f} |")

    best = max(((k, e, a[k][str(e)] - b[k][str(e)]) for k in ("fgsm", "pgd") for e in eps_list),
               key=lambda t: t[2])
    pgd_stronger = sum(b["pgd"][str(e)] <= b["fgsm"][str(e)] for e in eps_list)
    fallback = "fallback" in b["dataset"]
    note = ("> **Lưu ý:** số liệu dưới đây chạy trên bộ dữ liệu dự phòng "
            "(sklearn-digits, ~1.4k ảnh train) vì không tải được MNIST. "
            "Hãy chạy lại 2 script trên máy có mạng để lấy số liệu MNIST chính thức "
            "rồi chạy lại file này.\n\n") if fallback else ""

    advanced_method = ""
    advanced_result = ""
    advanced_comment = ""
    advanced_command = ""
    if advanced:
        settings = advanced["settings"]
        advanced_method = (
            f"\n- **Tấn công tối ưu nâng cao:** C&W-L2 (confidence=0, "
            f"{settings['cw_binary_search_steps']} bước binary search, tối đa "
            f"{settings['cw_max_iter']} vòng, c ban đầu={settings['cw_initial_const']}) "
            "được so sánh với PGD-L∞ "
            f"(ε={settings['pgd_eps']}) trên đúng cùng {advanced['n_test']} mẫu. "
            "Do hai thuật toán tối ưu hai chuẩn khác nhau, đánh giá dùng đồng thời "
            "robust accuracy, ASR và kích thước nhiễu L2/L∞."
        )
        adv_rows = []
        for model_name, model_result in advanced["models"].items():
            for key, attack_name in (("pgd_linf", "PGD-L∞"), ("cw_l2", "C&W-L2")):
                r = model_result[key]
                p = r["perturbation"]
                adv_rows.append(
                    f"| {model_name} | {attack_name} | {pct(r['robust_accuracy'])} | "
                    f"{pct(r['attack_success_rate'])} | {p['mean_l2']:.4f} | "
                    f"{p['mean_linf']:.4f} |")
        advanced_result = f"""

### 3.1. So sánh C&W-L2 với PGD-L∞

| Mô hình | Tấn công | Robust accuracy | ASR trên mẫu đúng | L2 TB | L∞ TB |
|---|---|---:|---:|---:|---:|
{chr(10).join(adv_rows)}

![So sánh C&W và PGD](results/cw_vs_pgd.png)

ASR chỉ tính trên các mẫu được phân loại đúng ban đầu; robust accuracy dùng toàn bộ
{advanced['n_test']} mẫu trong mẫu số. C&W và PGD không dùng ngân sách tương đương,
do đó các cột L2/L∞ là phần bắt buộc khi diễn giải mức độ mạnh của tấn công.
"""
        comparison_notes = []
        for model_name, model_result in advanced["models"].items():
            pgd_ra = model_result["pgd_linf"]["robust_accuracy"]
            cw_ra = model_result["cw_l2"]["robust_accuracy"]
            stronger = "C&W-L2" if cw_ra < pgd_ra else "PGD-L∞"
            comparison_notes.append(
                f"{model_name}: {stronger} (PGD {pct(pgd_ra)}; C&W {pct(cw_ra)})")
        advanced_comment = (
            "\n- So sánh robust accuracy theo cấu hình đã thử — "
            + "; ".join(comparison_notes)
            + ". Đây là kết quả thực nghiệm, không phải khẳng định tuyệt đối giữa "
              "hai họ tấn công vì ngân sách L2/L∞ khác nhau."
        )
        advanced_command = "python member_modules/member2_adversarial_evasion/compare_cw_pgd.py"

    md = f"""# Báo cáo Thành viên 2 - Tấn công né tránh & đối kháng (Adversarial Evasion)

{note}## 1. Mục tiêu và phạm vi
- Hệ thống mục tiêu: `target_systems/classifier` (SimpleCNN, ảnh 28x28, 10 lớp).
- Dữ liệu: {b['dataset']}; {b['n_test']} ảnh kiểm thử.
- Ánh xạ chuẩn: MITRE ATLAS AML.T0015 (Evade ML Model) / AML.T0043 (Craft Adversarial Data); OWASP ML Top 10 - ML01 Input Manipulation Attack.

## 2. Phương pháp
- **Red Team:** FGSM và PGD (20 bước, bước = ε/4, 1 lần khởi tạo ngẫu nhiên) của IBM ART, chuẩn L∞, ảnh giới hạn trong [0, 1]. Mức ε: {', '.join(str(e) for e in eps_list)}.{advanced_method}
- **Blue Team:** Adversarial Training - mỗi batch 50% ảnh sạch + 50% ảnh PGD (ε = {a['train_eps']}, 10 bước), {a['epochs']} epoch, huấn luyện mô hình mới từ đầu.

## 3. Kết quả
Độ chính xác trên ảnh sạch: trước phòng thủ **{pct(b['clean_accuracy'])}**, sau phòng thủ **{pct(a['clean_accuracy'])}** (đánh đổi: mô hình bền hơn thường kém hơn một chút trên ảnh sạch).

| Tấn công | ε | Trước phòng thủ | Sau phòng thủ | Phục hồi (điểm %) |
|---|---|---|---|---|
{chr(10).join(rows)}

![Độ chính xác theo epsilon](results/accuracy_vs_epsilon.png)
{advanced_result}

## 4. Nhận xét
- Chưa phòng thủ: độ chính xác giảm từ {pct(b['clean_accuracy'])} xuống {pct(b['pgd'][lo])} (PGD, ε={lo}) và {pct(b['pgd'][hi])} (PGD, ε={hi}); PGD thấp hơn hoặc bằng FGSM ở {pgd_stronger}/{len(eps_list)} mức ε.
- Phòng thủ có hiệu quả rõ nhất ở: {best[0].upper()} ε={best[1]} (+{100 * best[2]:.1f} điểm %).
- Ở ε={hi}, độ chính xác sau phòng thủ: FGSM {pct(a['fgsm'][hi])}, PGD {pct(a['pgd'][hi])}. Adversarial training **không** bảo vệ được ở mọi mức nhiễu: nhiễu càng lớn thì lợi ích càng giảm.
- Hạn chế: mô hình nhỏ; benchmark C&W chỉ dùng {advanced['n_test'] if advanced else b['n_test']} ảnh nên số liệu có thể dao động; chưa kiểm tra AutoAttack hoặc đầy đủ hiện tượng gradient masking.{advanced_comment}

## 5. Cách tái lập
```
python member_modules/member2_adversarial_evasion/assess_evasion.py
python member_modules/member2_adversarial_evasion/defense_adversarial_training.py
{advanced_command}
python member_modules/member2_adversarial_evasion/generate_report.py
```
Biến môi trường tùy chọn: `M2_N_TRAIN` (mặc định 10000), `M2_N_TEST` (1000), `M2_EPOCHS` (20).
Số liệu được ghi vào `shared_logging/audit_results.json` (module `member2_evasion`, `member2_defense`).
"""
    out = os.path.join(c.HERE, "BaoCao_ThanhVien2.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
