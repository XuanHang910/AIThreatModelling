# AI Threat Modelling & Security Evaluation

**Đề tài:** Nghiên cứu, mô hình hóa mối đe dọa và đánh giá an toàn hệ thống AI trong doanh nghiệp.

---

## 1. Kiến trúc Hệ thống Mục tiêu & Hạ tầng
- **Target 1 (`target_systems/classifier/`):** Mô hình thị giác máy tính `SimpleCNN` (28×28, 10 lớp MNIST).
- **Target 2 (`target_systems/rag_service/`):** Dịch vụ Chatbot RAG giả lập kết nối kho tài liệu nội bộ chứa thông tin nhạy cảm (`sensitive_docs.txt`).
- **Shared Logging (`shared_logging/`):** Hệ thống ghi log thống nhất vào `audit_results.json`.
- **Dashboard Demo (`app_demo.py`):** Giao diện Web trực quan đọc dữ liệu động từ JSON, chạy tấn công Evasion, Chatbot Guardrails và minh họa Trigger Backdoor theo thời gian thực.

---

## 2. Phân công & Kết quả 5 Thành viên

| Thành viên | Chuyên đề | Kết quả thực nghiệm chính |
|---|---|---|
| **TV1 (Lead)** | Kiến trúc, Threat Matrix & Audit | Thiết lập khung **STRIDE / MITRE ATLAS / OWASP LLM Top 10**, xây dựng bộ tổng hợp `audit_aggregator.py` xuất `AuditReport.md` và Web Dashboard `app_demo.py`. |
| **TV2 (Evasion)** | Tấn công Né tránh & Phục hồi | Dùng IBM ART (FGSM/PGD) kéo Acc từ **98.5%** xuống **0.7%** (PGD ε=0.3). **Adversarial Training** phục hồi lên **68.6%** (PGD) và **79.7%** (FGSM). So sánh C&W-L2 vs PGD-L∞ chỉ ra giới hạn không gian nhiễu. |
| **TV3 (LLM Sec)** | Prompt Injection & Cross-Testing | Phát hiện tỷ lệ rò rỉ RAG gốc **66.7%** (8/12 prompts). Thiết kế 7 payload bypass nâng cao (Base64, zero-width, DAN) kiểm thử chéo TV5 $\rightarrow$ sau vá v2 tỷ lệ bypass về **0.0%**. |
| **TV4 (Poison/Priv)** | Backdoor Poisoning & Privacy | Clean-label Backdoor (5% nhiễm) đạt ASR **41.7%**. Isolation Forest (0.20) giảm ASR xuống **15.0%**, Spectral Signatures bóc tách **26.5%**. **DP-SGD** hạ MIA Accuracy từ **59.4%** xuống **51.7%**. |
| **TV5 (Guardrails)** | Runtime Guardrails Proxy | Kiến trúc lọc 2 tầng (Input Normalization/Base64 + Output Redaction) đưa rò rỉ về **0.0%**, False Positive **0.0%** với độ trễ chỉ **0.036 ms/request**. |

---

## 3. Hướng dẫn Chạy Demo Giao diện
```powershell
python app_demo.py
```
Truy cập trình duyệt tại: **`http://localhost:8000`**
