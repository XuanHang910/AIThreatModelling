# Thành viên 2 - Trung Hiếu  - Adversarial Evasion

Chạy lần lượt:

```
python member_modules/member2_adversarial_evasion/assess_evasion.py              # Red Team: FGSM/PGD
python member_modules/member2_adversarial_evasion/defense_adversarial_training.py  # Blue Team
python member_modules/member2_adversarial_evasion/generate_report.py             # sinh BaoCao_ThanhVien2.md
```

Đầu ra nằm trong `results/` (JSON, `comparison_table.md`, `accuracy_vs_epsilon.png`) và
`BaoCao_ThanhVien2.md`; số liệu cũng được ghi vào `shared_logging/audit_results.json`.

Dữ liệu: MNIST (tự tải); nếu không có mạng sẽ dùng sklearn-digits làm dự phòng (có ghi trong kết quả).
Tùy chọn: `M2_N_TRAIN`, `M2_N_TEST`, `M2_EPOCHS`.
