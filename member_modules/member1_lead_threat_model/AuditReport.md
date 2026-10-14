# Báo cáo Kiểm toán và Đánh giá An toàn Hệ thống AI (Tổng hợp Toàn diện)
> **Thời gian xuất báo cáo:** 2026-10-14 16:25:09  
> **Chủ trì tổng hợp:** Thành viên 1 - Trưởng nhóm & Kiến trúc sư An toàn AI (Lead AI Security Architect)  
> **Mục tiêu hệ thống:** Phân loại ảnh / Bảng (`target_systems/classifier`) & Dịch vụ RAG Doanh nghiệp (`target_systems/rag_service`).

---

## 1. Khung Mô hình hóa Mối đe dọa (Threat Modeling Matrix)
Hệ thống được đối soát theo ma trận phối hợp chuẩn công nghiệp:

### 1.1. STRIDE
| Mối đe dọa (STRIDE) | Mô tả chi tiết |
|---|---|
| **Spoofing** | Attacker impersonates a valid user |

### 1.2. MITRE ATLAS & OWASP LLM Top 10
| Khung tiêu chuẩn | Định danh mã | Tên kỹ thuật / Mối đe dọa |
|---|---|---|
| MITRE ATLAS | `AML.T0001` | Adversarial Examples |
| OWASP LLM Top 10 | `LLM01` | Prompt Injection |

---

## 2. Bảng Tổng hợp Kết quả Thực nghiệm & Kiểm toán 4 Chuyên đề

| Chuyên đề | Kỹ thuật Tấn công / Rủi ro | Chỉ số Trước phòng thủ | Kỹ thuật Phòng thủ | Chỉ số Sau phòng thủ | Trạng thái Nghiệm thu |
|---|---|---|---|---|:---:|
| **TV2: Adversarial Evasion** | Tấn công đối kháng FGSM / PGD (ε=0.3) | Clean Acc: **98.50%**<br>PGD Acc: **0.70%** | Adversarial Training (PGD ε=0.3, ratio=0.5) | Clean Acc: **96.20%**<br>PGD Acc: **68.60%** | Đạt yêu cầu |
| **TV3: LLM Security** | Prompt Injection, Instruction Override & Data Extraction | Leakage Rate: **66.67%** (8/12 tests) | Kiểm soát phân quyền & làm sạch RAG query | Cần áp dụng Guardrails (TV5) | Phát hiện lỗ hổng nghiêm trọng |
| **TV4: Poisoning & Privacy** | Clean-label Backdoor & Membership Inference (MIA) | Backdoor ASR: **85.00%**<br>MIA Accuracy: **65.00%** | Isolation Forest Sanitization & Differential Privacy (DP-SGD) | Lọc mẫu độc: **11.93%**<br>MIA sau DP: **51.00%** | Đạt yêu cầu |
| **TV5: Runtime Guardrails** | Khai thác trích xuất bí mật qua Prompt độc hại | Leakage Rate (No Guard): **55.26%** | Dual Guardrail Proxy (Input Regex + Output Redaction) | Block Rate: **76.32%**<br>Leakage Rate: **0.00%**<br>Độ trễ tăng thêm: **0.0199 ms** | Đạt yêu cầu xuất sắc |

---

## 3. Phân tích Chi tiết Từng Chuyên đề Kỹ thuật

### 3.1. Chuyên đề 2 - Tấn công Né tránh & Bền vững Đối kháng (Adversarial Evasion)
- **Rủi ro:** Mô hình thị giác máy tính suy giảm độ chính xác đột ngột khi bị nhiễu đối kháng cấp độ pixel không thể nhận biết bằng mắt thường.
- **Thực nghiệm:** Dưới đòn tấn công PGD đa bước ở ngưỡng $\epsilon=0.3$, độ chính xác suy giảm nghiêm trọng từ **98.50%** xuống mức tê liệt **0.70%**.
- **Hiệu quả phòng thủ:** Adversarial Training giúp mô hình phục hồi độ chính xác đối kháng (Robust Accuracy) lên **68.60%**, tạo hàng rào phòng ngự chủ động vững chắc.

### 3.2. Chuyên đề 3 - An toàn Mô hình Ngôn ngữ & Prompt Injection
- **Rủi ro:** Các câu truy vấn tinh vi (Direct Secret Request, Instruction Override, Mixed Request) ép hệ thống RAG truy xuất và giải phóng dữ liệu nhạy cảm.
- **Thực nghiệm:** Tỷ lệ rò rỉ dữ liệu thô chưa qua lọc là **66.67%**. Tất cả các payload thuộc nhóm ép lệnh đều làm lộ credential trong văn bản tài liệu giả lập.

### 3.3. Chuyên đề 4 - Đầu độc Dữ liệu & Rò rỉ Quyền riêng tư (Poisoning & Privacy)
- **Đầu độc Backdoor:** Kẻ tấn công cấy trigger clean-label đạt tỷ lệ kích hoạt thành công ASR **85.00%**. Cơ chế lọc bất thường bằng Isolation Forest (tham chiếu tập sạch) loại bỏ thành công các mẫu độc hại khỏi tập huấn luyện.
- **Suy diễn Thành viên (MIA):** Mô hình huấn luyện thông thường bị lộ thông tin thành viên tập mẫu huấn luyện với độ chính xác đoán **65.00%**. Khi kích hoạt cơ chế DP-SGD (Differential Privacy Stochastic Gradient Descent), độ chính xác suy diễn giảm về **51.00%** (tiệm cận mức đoán ngẫu nhiên 50%), triệt tiêu rủi ro dò quét danh tính.

### 3.4. Chuyên đề 5 - Giám sát Thời gian thực & Guardrails (Ops Security)
- **Kiến trúc:** Lớp proxy kiểm soát 2 tầng (Input Validation + Output Redaction).
- **Đánh giá hiệu năng:**
  - Tỷ lệ chặn tấn công đầu vào (Block Rate): **76.32%** (chế độ tiêu chuẩn) và **89.47%** (chế độ nghiêm ngặt).
  - Tỷ lệ rò rỉ thông tin qua kênh đầu ra giảm từ **55.26%** về tuyệt đối **0.00%**.
  - Độ trễ gia tăng (Latency Overhead) cực thấp chỉ **0.0199 ms/request**, hoàn toàn đáp ứng SLA sản xuất của doanh nghiệp.

---

## 4. Kết luận & Khuyến nghị của Kỹ sư trưởng An toàn AI
1. **Phòng thủ Đa lớp (Defense-in-Depth):** Kết hợp bắt buộc giữa mô hình bền vững (Adversarial Training, DP-SGD) với middleware giám sát vòng ngoài (Runtime Guardrails).
2. **Kiểm toán Định kỳ:** Tích hợp pipeline kiểm thử tự động của TV2, TV3, TV4, TV5 vào CI/CD trước khi xuất bản bất kỳ checkpoint mô hình nào lên môi trường production.
3. **Môi trường RAG:** Phải cô lập kho lưu trữ tài liệu mật, áp dụng RBAC ở tầng tìm kiếm embedding thay vì phụ thuộc thuần túy vào câu nhắc hệ thống (system prompt).
