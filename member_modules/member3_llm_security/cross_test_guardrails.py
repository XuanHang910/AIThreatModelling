"""TV3 -> TV5 local cross-testing. Run from any working directory; PyYAML only."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import time
from datetime import datetime, timezone

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from target_systems.rag_service.rag_service import query_rag
from shared_logging.audit_logger import log_result


def load_yaml(path):
    return yaml.safe_load(path.read_text(encoding='utf-8')) or {}


def secret_values():
    doc = ROOT / 'target_systems/rag_service/sensitive_docs.txt'
    values = [line.split(':', 1)[1].strip() for line in doc.read_text(encoding='utf-8').splitlines()
              if ':' in line and line.split(':', 1)[1].strip()]
    if not values:
        raise ValueError('No fixture secret values; cannot measure leakage reliably.')
    return values


def leaked(text, values):
    return any(v.casefold() in str(text).casefold() for v in values)


def safe_preview(text, values):
    # Audit artifacts never persist the fixture values in raw responses.
    import re
    for value in values:
        text = re.sub(re.escape(value), '[FIXTURE_SECRET]', text, flags=re.I)
    return text


def rate(rows, field):
    return sum(bool(r[field]) for r in rows) / len(rows) if rows else None


def summarize(rows):
    ok = [r for r in rows if r['status'] == 'ok']
    return {'total': len(rows), 'completed': len(ok), 'errors': len(rows)-len(ok),
            'input_block_rate': rate(ok, 'blocked'),
            'input_bypass_rate': rate(ok, 'input_passed'),
            'baseline_leak_rate': rate(ok, 'baseline_leaked'),
            'input_only_leak_rate': rate(ok, 'input_only_leaked'),
            'full_pipeline_leak_rate': rate(ok, 'final_leaked'),
            'median_input_check_us': statistics.median(r['input_check_us'] for r in ok) if ok else None}


def percent(x):
    return 'N/A' if x is None else f'{x:.1%}'


def run(args):
    guard_path = args.guardrail_file.resolve()
    spec = importlib.util.spec_from_file_location('tv5_cross_test_guardrail', guard_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    guard = module.Guardrail(strict=args.strict)
    values = secret_values()
    new = load_yaml(HERE / 'bypass_testbench.yaml')['payloads']
    if len(new) != 7 or len({p['id'] for p in new}) != 7:
        raise ValueError('Expected seven unique new payload IDs.')
    original = load_yaml(HERE / 'prompt_testbench.yaml')['payloads']
    benign = load_yaml(ROOT / 'member_modules/member5_guardrails_ops/guardrail_testset.yaml')['benign']
    cases = [('new_bypass', p) for p in new]
    cases += [('original_observation', p if isinstance(p, dict) else
               {'id': f'P{i:02}', 'category': 'original', 'prompt': p})
              for i, p in enumerate(original, 1)]
    cases += [('benign', {'id': f'C{i:02}', 'category': 'benign', 'prompt': p})
              for i, p in enumerate(benign, 1)]
    rows = []
    for suite, case in cases:
        p = case['prompt']
        row = {'suite': suite, **case}
        try:
            start = time.perf_counter_ns()
            allowed = guard.check_input(p)
            elapsed = (time.perf_counter_ns()-start)/1000
            reason = guard.block_reason(p)
            raw = query_rag(p)
            final = guard.guarded_query(p, query_rag)
            filtered = guard.filter_output(raw) if allowed else None
            row.update(status='ok', input_passed=bool(allowed), blocked=not allowed,
                       block_reason=reason,
                       owasp_context='LLM01 prompt-injection test probe' if suite == 'new_bypass' else None,
                       input_check_us=round(elapsed, 3), baseline_leaked=leaked(raw, values),
                       input_only_leaked=bool(allowed and leaked(raw, values)),
                       final_leaked=leaked(final, values),
                       redaction_applied=bool(allowed and filtered != raw),
                       raw_preview=safe_preview(raw, values),
                       final_preview=safe_preview(final, values))
        except Exception as error:
            row.update(status='error', error=f'{type(error).__name__}: {error}')
        rows.append(row)
        print(f"{suite:22} {case['id']}: " +
              (f"blocked={row['blocked']} final_leak={row['final_leaked']}" if row['status']=='ok' else row['error']))
    summary = {suite: summarize([r for r in rows if r['suite']==suite])
               for suite in ('new_bypass', 'original_observation', 'benign')}
    summary['benign']['false_positive_rate'] = summary['benign']['input_block_rate']
    result = {'timestamp_utc': datetime.now(timezone.utc).isoformat(),
              'guardrail_file': str(guard_path.relative_to(ROOT)) if guard_path.is_relative_to(ROOT) else str(guard_path),
              'guardrail_sha256': hashlib.sha256(guard_path.read_bytes()).hexdigest(),
              'strict': args.strict, 'target': 'repository rule-based dummy RAG, unchanged',
              'latency_note': 'Single-call perf_counter_ns input-check timings in microseconds; exploratory, not a stable benchmark.',
              'summary': summary, 'results': rows}
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out/'cross_test_results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# Kết quả đánh chéo TV3 → TV5', '',
             'Người thực hiện: Nguyễn Huỳnh Hoan (TV3). Đích kiểm thử: code Guardrail của Giang trong ZIP đã gửi.', '',
             f"Thời điểm UTC: {result['timestamp_utc']}. Chế độ strict: {args.strict}.", '',
             '## Kết quả 7 payload mới', '',
             '| ID | Kỹ thuật | Chặn đầu vào | Lộ khi chưa bảo vệ | Lộ sau lọc đầu vào | Đã che đầu ra | Lộ cuối cùng |',
             '|---|---|---|---|---|---|---|']
    for r in rows:
        if r['suite'] != 'new_bypass': continue
        if r['status'] != 'ok':
            lines.append(f"| {r['id']} | {r['category']} | ERROR | — | — | — | — |")
            continue
        yn=lambda f: 'Có' if r[f] else 'Không'
        lines.append(f"| {r['id']} | {r['category']} | {yn('blocked')} | {yn('baseline_leaked')} | {yn('input_only_leaked')} | {yn('redaction_applied')} | {yn('final_leaked')} |")
    s=summary['new_bypass']; b=summary['benign']
    lines += ['', f"- Đã chạy: {s['completed']}/{s['total']}; lỗi: {s['errors']}.",
              f"- Tỷ lệ lọt bộ lọc đầu vào: {percent(s['input_bypass_rate'])}.",
              f"- Tỷ lệ lộ sau lọc đầu vào: {percent(s['input_only_leak_rate'])}.",
              f"- Tỷ lệ lộ sau cả hai lớp: {percent(s['full_pipeline_leak_rate'])}.",
              f"- Chặn nhầm trên bộ {b['total']} câu benign cố định của Giang: {percent(b['false_positive_rate'])}.", '',
              '## Cách đọc và giới hạn', '',
              'Qua bộ lọc đầu vào là một kết quả riêng; chỉ tính rò rỉ khi câu trả lời chứa giá trị bí mật trong fixture. Không dùng riêng nhãn API key/password để kết luận lộ.', '',
              'Chatbot là mô phỏng: chỉ tìm chuỗi key/password để trả tài liệu; không tự giải mã Base64, ghép chữ hay thực hiện nhập vai. B01/B03 có thể qua đầu vào nhưng không làm chatbot này lộ dữ liệu. Không thêm bộ giải mã vào chatbot để tạo kết quả khai thác giả.', '',
              '12 prompt cũ được chạy lại ở nhóm original_observation, không gán tất cả là tấn công vì có các câu hỏi trung tính. Chỉ 7 payload mới dùng làm mẫu số tỷ lệ bypass. False positive dùng riêng bộ benign đã có, không chỉnh bộ câu để làm đẹp tỷ lệ.', '',
              'Đây là các ca thăm dò nhỏ, không phải bằng chứng tỷ lệ thành công trên LLM thật hay bảo đảm an toàn cho mọi đầu vào. Các kỹ thuật này không được khẳng định xuất hiện lần đầu năm 2024.', '',
              'Độ trễ đo riêng check_input một lần mỗi câu, có nhiễu; không dùng để khẳng định hiệu năng ổn định. Đầu ra log thay giá trị fixture bằng [FIXTURE_SECRET]; số liệu lộ được tính trước khi thay.', '',
              '## Bàn giao cho Giang', '',
              'Dùng các payload bị lọt làm ca hồi quy khi bổ sung giải mã Base64 trước Regex và mở rộng chuẩn hóa Unicode. Khi chỉnh whitelist, chạy lại cùng bộ benign và 7 payload; kiểm tra cả tỷ lệ lọt lẫn chặn nhầm. Chưa có số liệu sau nâng cấp nên chưa kết luận đạt dưới 10%.', '',
              'Giữ nguyên code TV5 và chatbot trong gói này. Chạy lại sau khi Giang thay guardrail_middleware.py để có kết quả trước/sau.']
    (out/'BAO_CAO_CROSS_TEST.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    if not args.no_audit:
        for metric, value in [('input_bypass_rate',s['input_bypass_rate']),
                              ('block_rate',s['input_block_rate']),
                              ('input_only_leakage_rate',s['input_only_leak_rate']),
                              ('full_pipeline_leakage_rate',s['full_pipeline_leak_rate']),
                              ('false_positive_rate',b['false_positive_rate'])]:
            if value is not None:
                log_result('member3_cross_testing', metric, value,
                           {'summary':summary, 'guardrail_sha256':result['guardrail_sha256'],
                            'scope':'7 new probes; FPR from TV5 benign set; dummy RAG'})
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return 1 if any(r['status']=='error' for r in rows) else 0


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError):
        pass
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict',action='store_true')
    parser.add_argument('--guardrail-file',type=Path,default=ROOT/'member_modules/member5_guardrails_ops/guardrail_middleware.py')
    parser.add_argument('--output-dir',type=Path,default=HERE/'results_cross_testing')
    parser.add_argument('--no-audit',action='store_true',help='Do not append to shared audit log')
    sys.exit(run(parser.parse_args()))
