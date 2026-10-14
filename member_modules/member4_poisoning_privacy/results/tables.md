**Bảng 1. Tấn công backdoor clean-label** (dataset MNIST, lớp mục tiêu 7, 10000 mẫu huấn luyện, trung bình 3 seed)

Mô hình sạch: độ chính xác 97.50%, ASR tự nhiên của trigger 0.32%.

| Tỉ lệ nhiễm độc | Số mẫu độc | ASR plain (%) | ASR adversarial (%) | Độ chính xác sạch adversarial (%) |
|---|---|---|---|---|
| 0.5% | 50 | 0.36 ± 0.19 | 2.00 ± 0.98 | 97.48 |
| 1.0% | 100 | 0.65 ± 0.26 | 9.65 ± 2.76 | 97.48 |
| 2.0% | 200 | 0.64 ± 0.23 | 17.22 ± 4.25 | 97.17 |
| 5.0% | 500 | 8.77 ± 5.15 | 41.73 ± 15.13 | 97.40 |

**Bảng 2. Làm sạch dữ liệu bằng Isolation Forest** (nhiễm độc 5% = 500 mẫu độc; trước khi lọc: ASR 33.58%, độ chính xác 96.92%)

| Cách | Mức | Số mẫu bị loại | Mẫu độc bị loại (%) | Mẫu sạch bị loại nhầm (%) | ASR sau lọc (%) | Độ chính xác sau lọc (%) |
|---|---|---|---|---|---|---|
| Không giám sát | 0.05 | 504 | 4.1 | 5.1 | 33.17 | 96.78 |
| Không giám sát | 0.10 | 1003 | 8.7 | 10.1 | 17.03 | 95.88 |
| Không giám sát | 0.20 | 2002 | 17.4 | 20.2 | 22.34 | 95.12 |
| Có tập tham chiếu | 0.05 | 528 | 4.1 | 5.3 | 31.93 | 97.43 |
| Có tập tham chiếu | 0.10 | 996 | 11.9 | 9.9 | 35.05 | 96.42 |
| Có tập tham chiếu | 0.20 | 1999 | 30.5 | 19.4 | 15.01 | 95.12 |

**Bảng 3. Membership Inference Attack và phòng thủ** (500 mẫu huấn luyện, 60 epoch, trung bình 5 seed; 50% = đoán mò)

| Cấu hình | Độ chính xác MIA (%) | AUC | Độ chính xác huấn luyện (%) | Độ chính xác kiểm thử (%) |
|---|---|---|---|---|
| Không phòng thủ | 59.4 | 0.572 | 100.0 | 91.8 |
| Dropout + WD | 58.0 | 0.594 | 99.9 | 94.2 |
| DP-SGD σ=1 | 51.7 | 0.519 | 77.9 | 73.4 |
| DP-SGD σ=2 | 52.6 | 0.523 | 76.8 | 72.4 |

Ghi chú: DP-SGD là bản tự cài đặt (cắt gradient từng mẫu + nhiễu Gaussian), không tính ngân sách epsilon chính thức.
