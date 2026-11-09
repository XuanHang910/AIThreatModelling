# Thành viên 2 - Trung Hiếu  - Adversarial Evasion

Chạy lần lượt:

```
python member_modules/member2_adversarial_evasion/assess_evasion.py              # Red Team: FGSM/PGD
python member_modules/member2_adversarial_evasion/defense_adversarial_training.py  # Blue Team
python member_modules/member2_adversarial_evasion/compare_cw_pgd.py              # C&W-L2 vs PGD-Linf
python member_modules/member2_adversarial_evasion/generate_report.py             # sinh BaoCao_ThanhVien2.md
```

Đầu ra nằm trong `results/` (JSON, `comparison_table.md`, `accuracy_vs_epsilon.png`) và
`BaoCao_ThanhVien2.md`; số liệu cũng được ghi vào `shared_logging/audit_results.json`.

Dữ liệu: MNIST (tự tải); nếu không có mạng sẽ dùng sklearn-digits làm dự phòng (có ghi trong kết quả).

Benchmark C&W dùng cùng mẫu và checkpoint với PGD, xuất
`results/cw_vs_pgd_results.json`, `results/cw_vs_pgd_comparison.md` và
`results/cw_vs_pgd.png`. Mặc định script đánh giá 100 mẫu trên cả mô hình sạch và
mô hình robust. C&W tối ưu chuẩn L2 còn PGD bị chặn bởi epsilon L-inf, vì vậy bảng
báo cáo đồng thời robust accuracy, attack success rate và kích thước nhiễu L2/L-inf.

Tùy chọn chung: `M2_N_TRAIN`, `M2_N_TEST`, `M2_EPOCHS`. Tùy chọn benchmark:
`M2_CW_N_TEST`, `M2_COMPARE_PGD_EPS`, `M2_CW_MAX_ITER`,
`M2_CW_BINARY_SEARCH_STEPS`, `M2_CW_BATCH`, `M2_CW_INITIAL_CONST`,
`M2_CW_LEARNING_RATE`; hoặc xem `compare_cw_pgd.py --help`.
