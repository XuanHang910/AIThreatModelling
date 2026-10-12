import json
import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(__file__), 'audit_results.json')

def log_result(module_name: str, metric_name: str, value: float, details: dict = None):
    """Ghi nhận kết quả đánh giá vào file JSON dùng chung."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "module": module_name,
        "metric": metric_name,
        "value": value,
        "details": details or {}
    }
    
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        except:
            pass
            
    logs.append(entry)
    
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        json.dump(logs, f, indent=4)
    
    print(f"[AUDIT LOG] {module_name} | {metric_name}: {value}")
