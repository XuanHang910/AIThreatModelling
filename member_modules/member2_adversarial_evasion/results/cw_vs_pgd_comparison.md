# So sánh độ bền vững: C&W-L2 và PGD-L∞

Dataset: MNIST; cùng 100 mẫu cho mỗi mô hình. PGD dùng ε=0.3; C&W dùng 5 bước binary search × tối đa 50 vòng tối ưu, c ban đầu=1.0.

| Mô hình | Tấn công | Robust accuracy | ASR trên mẫu đúng | L2 TB | L∞ TB | Thời gian (s) |
|---|---|---:|---:|---:|---:|---:|
| clean | PGD-L∞ | 0.0% | 100.0% | 5.7692 | 0.3000 | 0.2 |
| clean | C&W-L2 | 2.0% | 97.9% | 2.3901 | 0.6687 | 66.0 |
| robust | PGD-L∞ | 73.0% | 23.2% | 6.0268 | 0.3000 | 0.2 |
| robust | C&W-L2 | 23.0% | 75.8% | 2.6031 | 0.6803 | 79.9 |

ASR (attack success rate) chỉ tính trên các mẫu mô hình phân loại đúng ban đầu; robust accuracy dùng toàn bộ tập mẫu trong mẫu số.

> C&W tối thiểu hóa chuẩn L2 còn PGD bị chặn bởi ngân sách L∞. Vì vậy cần đọc độ chính xác/ASR cùng kích thước nhiễu, không coi hai ngân sách là tương đương.

- **clean:** PGD-L∞ cho robust accuracy thấp hơn (PGD 0.0%; C&W 2.0%) trong cấu hình này.
- **robust:** C&W-L2 cho robust accuracy thấp hơn (PGD 73.0%; C&W 23.0%) trong cấu hình này.
