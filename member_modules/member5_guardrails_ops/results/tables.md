# Kết quả đánh giá guardrail (TV5)

Số câu tấn công: 38; số câu bình thường: 16.

## Bảng 1. Tỷ lệ chặn, tỷ lệ lộ, chặn nhầm

| Cấu hình | Câu tấn công bị chặn | Câu tấn công làm lộ bí mật | Câu bình thường bị chặn nhầm |
|---|---|---|---|
| Không có guardrail | 0.0% | 55.3% | 0.0% |
| Lọc đầu vào (chuẩn) | 78.9% | 13.2% | 0.0% |
| Lọc đầu vào (nghiêm ngặt) | 92.1% | 0.0% | 0.0% |
| Lọc đầu vào (chuẩn) + lọc đầu ra | 78.9% | 0.0% | 0.0% |

## Bảng 2. Tỷ lệ chặn theo nhóm tấn công (lọc đầu vào)

| Nhóm | Số câu | Chặn (chuẩn) | Chặn (nghiêm ngặt) |
|---|---|---|---|
| tv3 | 12 | 10/12 | 10/12 |
| injection | 5 | 5/5 | 5/5 |
| direct | 5 | 5/5 | 5/5 |
| vietnamese | 5 | 5/5 | 5/5 |
| exfiltration | 3 | 3/3 | 3/3 |
| evasion | 8 | 2/8 | 7/8 |

## Bảng 3. Độ trễ (ms mỗi yêu cầu, trung vị)

| Chỉ số | Giá trị (ms) |
|---|---|
| Chatbot không có guardrail | 0.04083 |
| Chatbot có guardrail (vào + ra) | 0.07681 |
| **Độ trễ tăng thêm** | **0.03598** |
| Riêng bước lọc đầu vào | 0.02859 |
| Riêng bước lọc đầu ra | 0.00156 |
