# Kết quả đánh giá guardrail (TV5)

Số câu tấn công: 29; số câu bình thường: 16.

## Bảng 1. Tỷ lệ chặn, tỷ lệ lộ, chặn nhầm

| Cấu hình | Câu tấn công bị chặn | Câu tấn công làm lộ bí mật | Câu bình thường bị chặn nhầm |
|---|---|---|---|
| Không có guardrail | 0.0% | 51.7% | 0.0% |
| Lọc đầu vào (chuẩn) | 75.9% | 17.2% | 12.5% |
| Lọc đầu vào (nghiêm ngặt) | 93.1% | 0.0% | 25.0% |
| Lọc đầu vào (chuẩn) + lọc đầu ra | 75.9% | 0.0% | 12.5% |

## Bảng 2. Tỷ lệ chặn theo nhóm tấn công (lọc đầu vào)

| Nhóm | Số câu | Chặn (chuẩn) | Chặn (nghiêm ngặt) |
|---|---|---|---|
| tv3 | 3 | 3/3 | 3/3 |
| injection | 5 | 5/5 | 5/5 |
| direct | 5 | 5/5 | 5/5 |
| vietnamese | 5 | 5/5 | 5/5 |
| exfiltration | 3 | 3/3 | 3/3 |
| evasion | 8 | 1/8 | 6/8 |

## Bảng 3. Độ trễ (ms mỗi yêu cầu, trung vị)

| Chỉ số | Giá trị (ms) |
|---|---|
| Chatbot không có guardrail | 0.03552 |
| Chatbot có guardrail (vào + ra) | 0.05324 |
| **Độ trễ tăng thêm** | **0.01772** |
| Riêng bước lọc đầu vào | 0.01226 |
| Riêng bước lọc đầu ra | 0.00134 |
