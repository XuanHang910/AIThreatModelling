"""Runtime Guardrail (Thành viên 5).

Lớp "bảo vệ cổng vào - ra" đặt trước chatbot RAG:

    câu hỏi ──▶ check_input()  ──(bị chặn)──▶ trả lời từ chối
                    │ (cho qua)
                    ▼
               chatbot RAG
                    │
                    ▼
              filter_output()  ──▶ trả lời đã che thông tin nhạy cảm

Hai lớp độc lập (phòng thủ nhiều tầng):
  1. Bộ lọc ĐẦU VÀO: chuẩn hóa câu hỏi rồi đối chiếu với các mẫu (regex) thuộc
     3 nhóm: tiêm lệnh (prompt injection), đòi thông tin nhạy cảm, đòi xuất toàn bộ tài liệu.
  2. Bộ lọc ĐẦU RA: nếu chatbot lỡ trả lời có dạng "nhãn: giá trị bí mật" thì che đi.

Giao diện cũ được giữ nguyên: Guardrail().check_input(text) -> True nếu cho qua,
False nếu bị chặn.
"""
import re
import unicodedata
from typing import Callable, List, Optional, Tuple

REFUSAL = "Yêu cầu bị từ chối bởi guardrail."
REDACTED = "[REDACTED]"


def normalize(text: str) -> str:
    """Chuẩn hóa để khó lách bằng cách đổi kiểu viết.

    - bỏ dấu tiếng Việt (mật khẩu -> mat khau), đổi đ -> d
    - bỏ ký tự vô hình (zero-width), đổi chữ hoa thành thường
    - api_key / api-key -> "api key", gộp nhiều khoảng trắng thành một
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("đ", "d").replace("Đ", "D")
    text = unicodedata.normalize("NFD", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    text = re.sub(r"[​-‏⁠﻿]", "", text)
    text = text.lower()
    text = re.sub(r"[_\-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# (nhóm, tên luật, regex). Regex chạy trên văn bản ĐÃ chuẩn hóa (không dấu, chữ thường).
_RULES: List[Tuple[str, str, str]] = [
    # ---- Nhóm 1: tiêm lệnh / bẻ khóa (prompt injection, jailbreak) ----
    ("injection", "ignore_instructions",
     r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}"
     r"\b(previous|prior|above|earlier|all|any|your|the)\b.{0,30}"
     r"\b(instructions?|rules?|prompts?|guidelines?|polic(?:y|ies)|restrictions?)\b"),
    ("injection", "ignore_instructions_vi",
     r"\b(bo qua|quen|vo hieu hoa)\b.{0,40}\b(quy tac|huong dan|chi dan|chi thi|lenh)\b"),
    ("injection", "jailbreak_keywords",
     r"\b(system prompt|developer mode|jailbreak|dan mode|do anything now)\b"),
    ("injection", "role_override",
     r"\b(you are now|act as|pretend (?:to be|you))\b.{0,30}"
     r"\b(admin|administrator|root|developer|unrestricted|ceo)\b"),
    ("injection", "role_override_simple", r"\byou are now\b"),
    # ---- Nhóm 2: đòi thông tin nhạy cảm ----
    ("sensitive", "named_key_or_token",
     r"\b(api|secret|access|private|ssh|encryption|master|admin|root|auth)\s?(keys?|tokens?)\b"),
    ("sensitive", "sensitive_words",
     r"\b(secrets?|credentials?|passwd|passwords?|passphrase|tokens?)\b"),
    ("sensitive", "sensitive_words_vi",
     r"\b(mat khau|khoa bi mat|khoa api|thong tin dang nhap|tai khoan quan tri)\b"),
    ("sensitive", "admin_login",
     r"\b(admin|administrator|quan tri)\b.{0,20}\b(pass|login|account)\b"),
    ("sensitive", "spaced_password",
     r"p[\s.*]*a[\s.*]*s[\s.*]*s[\s.*]*w[\s.*]*o[\s.*]*r[\s.*]*d"),
    # ---- Nhóm 3: đòi xuất toàn bộ tài liệu ----
    ("exfiltration", "dump_all",
     r"\b(print|dump|list|show|reveal|display|output|leak|export|summari[sz]e)\b.{0,25}"
     r"\b(all|every|entire|whole|full)\b.{0,25}\b(documents?|files?|data|contents?|records?)\b"),
    ("exfiltration", "dump_all_vi",
     r"\b(in|liet ke|hien thi|cho xem|tiet lo)\b.{0,25}\b(toan bo|tat ca)\b.{0,25}"
     r"\b(tai lieu|du lieu|noi dung|tep)\b"),
    ("exfiltration", "sensitive_docs_file", r"sensitive docs"),
]

# Chế độ nghiêm ngặt: chặn cả chữ "key" đứng riêng. An toàn hơn nhưng chặn nhầm nhiều hơn
# (ví dụ "key performance indicators").
_STRICT_RULES: List[Tuple[str, str, str]] = [
    ("sensitive", "bare_key", r"\bkeys?\b"),
]

# Mẫu che đầu ra: "<nhãn nhạy cảm>: <giá trị>" hoặc "<nhãn> = <giá trị>"
_OUTPUT_PATTERN = re.compile(
    r"(?:secret\s+api\s+key|admin\s+password|api[\s_-]?key|password|passwd|secret|token)"
    r"\s*[:=]\s*\S+",
    re.IGNORECASE,
)


class Guardrail:
    def __init__(self, strict: bool = False):
        self.strict = strict
        rules = _RULES + (_STRICT_RULES if strict else [])
        self._rules = [(cat, name, re.compile(rx)) for cat, name, rx in rules]

    # ---------- đầu vào ----------
    def block_reason(self, text: str) -> Optional[str]:
        """Trả về 'nhóm:tên_luật' nếu câu hỏi bị chặn, ngược lại trả về None."""
        norm = normalize(text)
        for cat, name, rx in self._rules:
            if rx.search(norm):
                return f"{cat}:{name}"
        return None

    def check_input(self, text: str) -> bool:
        """True = cho qua, False = chặn (giữ nguyên giao diện của bản khung)."""
        return self.block_reason(text) is None

    # ---------- đầu ra ----------
    def filter_output(self, text: str) -> str:
        """Che các chuỗi có dạng 'nhãn nhạy cảm: giá trị' trong câu trả lời."""
        return _OUTPUT_PATTERN.sub(REDACTED, text)

    # ---------- gộp cả hai lớp ----------
    def guarded_query(self, prompt: str, rag_fn: Callable[[str], str]) -> str:
        if not self.check_input(prompt):
            return REFUSAL
        return self.filter_output(rag_fn(prompt))
