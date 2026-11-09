"""Benchmark C&W-L2 against PGD-Linf on the same correctly classified samples.

C&W and PGD optimise different perturbation norms, so comparing accuracy alone is
not sufficient.  This script also reports attack success rate and realised L2/Linf
perturbation sizes for every model/attack pair.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Dict, Tuple

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  # noqa: E402


DEFAULT_N_TEST = int(os.environ.get("M2_CW_N_TEST", "100"))
DEFAULT_PGD_EPS = float(os.environ.get("M2_COMPARE_PGD_EPS", str(c.HEADLINE_EPS)))
DEFAULT_CW_MAX_ITER = int(os.environ.get("M2_CW_MAX_ITER", "50"))
DEFAULT_CW_BINARY_STEPS = int(os.environ.get("M2_CW_BINARY_SEARCH_STEPS", "5"))
DEFAULT_CW_BATCH = int(os.environ.get("M2_CW_BATCH", "32"))
DEFAULT_CW_INITIAL_CONST = float(os.environ.get("M2_CW_INITIAL_CONST", "1.0"))
DEFAULT_CW_LEARNING_RATE = float(os.environ.get("M2_CW_LEARNING_RATE", "0.01"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="So sanh C&W-L2 va PGD-Linf tren cung tap mau.")
    parser.add_argument(
        "--model", choices=("clean", "robust", "both"), default="both",
        help="checkpoint can danh gia (mac dinh: both)")
    parser.add_argument(
        "--n-test", type=int, default=DEFAULT_N_TEST,
        help="so mau test toi da cho moi checkpoint")
    parser.add_argument(
        "--pgd-eps", type=float, default=DEFAULT_PGD_EPS,
        help="epsilon L-inf cua PGD")
    parser.add_argument(
        "--cw-max-iter", type=int, default=DEFAULT_CW_MAX_ITER,
        help="so vong toi uu toi da cua C&W")
    parser.add_argument(
        "--cw-binary-steps", type=int, default=DEFAULT_CW_BINARY_STEPS,
        help="so buoc binary search hang so c cua C&W")
    parser.add_argument(
        "--cw-batch-size", type=int, default=DEFAULT_CW_BATCH,
        help="batch size cua C&W")
    parser.add_argument(
        "--cw-initial-const", type=float, default=DEFAULT_CW_INITIAL_CONST,
        help="hang so c ban dau cua C&W (mac dinh: 1.0)")
    parser.add_argument(
        "--cw-learning-rate", type=float, default=DEFAULT_CW_LEARNING_RATE,
        help="learning rate cua C&W (mac dinh: 0.01)")
    args = parser.parse_args()
    if args.n_test <= 0:
        parser.error("--n-test phai lon hon 0")
    if args.pgd_eps <= 0:
        parser.error("--pgd-eps phai lon hon 0")
    if (args.cw_max_iter <= 0 or args.cw_binary_steps <= 0 or
            args.cw_batch_size <= 0 or args.cw_initial_const <= 0 or
            args.cw_learning_rate <= 0):
        parser.error("cac tham so C&W phai lon hon 0")
    return args


def load_checkpoint(filename: str) -> torch.nn.Module:
    path = os.path.join(c.HERE, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Khong tim thay {path}. Hay chay assess_evasion.py va "
            "defense_adversarial_training.py truoc.")
    model = c.SimpleCNN()
    try:
        state = torch.load(path, map_location="cpu", weights_only=True)
    except TypeError:  # PyTorch cu chua co weights_only
        state = torch.load(path, map_location="cpu")
    model.load_state_dict(state)
    model.eval()
    return model


def perturbation_stats(x_adv: np.ndarray, x: np.ndarray,
                       successful: np.ndarray) -> Dict[str, float | None]:
    delta = (x_adv - x).reshape(len(x), -1)
    l2 = np.linalg.norm(delta, ord=2, axis=1)
    linf = np.linalg.norm(delta, ord=np.inf, axis=1)

    def mean_success(values: np.ndarray) -> float | None:
        return float(values[successful].mean()) if successful.any() else None

    return {
        "mean_l2": float(l2.mean()),
        "median_l2": float(np.median(l2)),
        "mean_linf": float(linf.mean()),
        "max_linf": float(linf.max()),
        "mean_l2_successful": mean_success(l2),
        "mean_linf_successful": mean_success(linf),
    }


def run_attack(classifier, attack, x: np.ndarray, y: np.ndarray,
               n_total: int) -> Tuple[Dict[str, object], np.ndarray]:
    started = time.perf_counter()
    # y is supplied explicitly to evaluate untargeted attacks against ground truth.
    x_adv = attack.generate(x=x, y=y)
    elapsed = time.perf_counter() - started
    pred_adv = classifier.predict(x_adv, batch_size=512).argmax(1)
    successful = pred_adv != y
    survivors = int((~successful).sum())
    result: Dict[str, object] = {
        "n_attacked": int(len(x)),
        "n_successful": int(successful.sum()),
        "attack_success_rate": float(successful.mean()),
        # Samples misclassified before the attack stay failures in the denominator.
        "robust_accuracy": float(survivors / n_total),
        "runtime_seconds": float(elapsed),
        "perturbation": perturbation_stats(x_adv, x, successful),
    }
    return result, x_adv


def evaluate_model(label: str, checkpoint: str, x: np.ndarray, y: np.ndarray,
                   args: argparse.Namespace) -> Dict[str, object]:
    from art.attacks.evasion import CarliniL2Method, ProjectedGradientDescent

    model = load_checkpoint(checkpoint)
    classifier = c.make_classifier(model)
    clean_pred = classifier.predict(x, batch_size=512).argmax(1)
    correct = clean_pred == y
    x_correct, y_correct = x[correct], y[correct]
    if not len(x_correct):
        raise RuntimeError(f"{label}: khong co mau nao duoc phan loai dung de tan cong")

    clean_accuracy = float(correct.mean())
    print(f"\n[{label}] clean accuracy={clean_accuracy:.2%}; "
          f"attack samples={len(x_correct)}/{len(x)}")

    pgd = ProjectedGradientDescent(
        classifier, norm=np.inf, eps=args.pgd_eps, eps_step=args.pgd_eps / 4,
        max_iter=20, num_random_init=1, batch_size=c.BATCH, verbose=False)
    print(f"[{label}] Running PGD-Linf (eps={args.pgd_eps})...")
    pgd_result, _ = run_attack(classifier, pgd, x_correct, y_correct, len(x))

    cw = CarliniL2Method(
        classifier, confidence=0.0, targeted=False,
        learning_rate=args.cw_learning_rate,
        binary_search_steps=args.cw_binary_steps, max_iter=args.cw_max_iter,
        initial_const=args.cw_initial_const, max_halving=5, max_doubling=5,
        batch_size=args.cw_batch_size, verbose=False)
    print(f"[{label}] Running C&W-L2 (max_iter={args.cw_max_iter}, "
          f"binary_steps={args.cw_binary_steps})...")
    cw_result, _ = run_attack(classifier, cw, x_correct, y_correct, len(x))

    for attack_name, result in (("PGD", pgd_result), ("C&W", cw_result)):
        p = result["perturbation"]
        print(f"  {attack_name}: robust_acc={result['robust_accuracy']:.2%}, "
              f"ASR={result['attack_success_rate']:.2%}, "
              f"mean_L2={p['mean_l2']:.4f}, mean_Linf={p['mean_linf']:.4f}, "
              f"time={result['runtime_seconds']:.1f}s")

    return {
        "checkpoint": checkpoint,
        "n_test": int(len(x)),
        "n_clean_correct": int(correct.sum()),
        "clean_accuracy": clean_accuracy,
        "pgd_linf": pgd_result,
        "cw_l2": cw_result,
    }


def fmt(value: float | None, digits: int = 4) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def write_markdown(results: Dict[str, object]) -> str:
    settings = results["settings"]
    lines = [
        "# So sánh độ bền vững: C&W-L2 và PGD-L∞",
        "",
        (f"Dataset: {results['dataset']}; cùng {results['n_test']} mẫu cho mỗi mô hình. "
         f"PGD dùng ε={settings['pgd_eps']}; C&W dùng "
         f"{settings['cw_binary_search_steps']} bước binary search × tối đa "
         f"{settings['cw_max_iter']} vòng tối ưu, c ban đầu="
         f"{settings['cw_initial_const']}."),
        "",
        "| Mô hình | Tấn công | Robust accuracy | ASR trên mẫu đúng | L2 TB | "
        "L∞ TB | Thời gian (s) |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for model_name, model_result in results["models"].items():
        for key, attack_name in (("pgd_linf", "PGD-L∞"), ("cw_l2", "C&W-L2")):
            attack_result = model_result[key]
            p = attack_result["perturbation"]
            lines.append(
                f"| {model_name} | {attack_name} | "
                f"{attack_result['robust_accuracy']:.1%} | "
                f"{attack_result['attack_success_rate']:.1%} | "
                f"{fmt(p['mean_l2'])} | {fmt(p['mean_linf'])} | "
                f"{attack_result['runtime_seconds']:.1f} |")
    lines.extend([
        "",
        "ASR (attack success rate) chỉ tính trên các mẫu mô hình phân loại đúng ban đầu; "
        "robust accuracy dùng toàn bộ tập mẫu trong mẫu số.",
        "",
        "> C&W tối thiểu hóa chuẩn L2 còn PGD bị chặn bởi ngân sách L∞. Vì vậy cần đọc "
        "độ chính xác/ASR cùng kích thước nhiễu, không coi hai ngân sách là tương đương.",
        "",
    ])
    for model_name, model_result in results["models"].items():
        pgd_ra = model_result["pgd_linf"]["robust_accuracy"]
        cw_ra = model_result["cw_l2"]["robust_accuracy"]
        stronger = "C&W-L2" if cw_ra < pgd_ra else "PGD-L∞"
        lines.append(
            f"- **{model_name}:** {stronger} cho robust accuracy thấp hơn "
            f"(PGD {pgd_ra:.1%}; C&W {cw_ra:.1%}) trong cấu hình này.")
    lines.append("")
    path = os.path.join(c.RESULTS_DIR, "cw_vs_pgd_comparison.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def write_chart(results: Dict[str, object]) -> str | None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        model_names = list(results["models"])
        x = np.arange(len(model_names))
        width = 0.36
        pgd = [results["models"][name]["pgd_linf"]["robust_accuracy"] for name in model_names]
        cw = [results["models"][name]["cw_l2"]["robust_accuracy"] for name in model_names]
        fig, ax = plt.subplots(figsize=(7, 4.5))
        ax.bar(x - width / 2, pgd, width, label="PGD-L∞", color="#c0392b")
        ax.bar(x + width / 2, cw, width, label="C&W-L2", color="#6c3483")
        ax.set_ylabel("Robust accuracy")
        ax.set_xticks(x)
        ax.set_xticklabels(model_names)
        ax.set_ylim(0, 1)
        ax.grid(axis="y", alpha=0.25)
        ax.legend()
        for bars in ax.containers:
            ax.bar_label(bars, labels=[f"{v:.1%}" for v in bars.datavalues], padding=3)
        fig.tight_layout()
        path = os.path.join(c.RESULTS_DIR, "cw_vs_pgd.png")
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path
    except Exception as exc:
        print(f"[WARN] Khong ve duoc bieu do: {exc}")
        return None


def main() -> None:
    args = parse_args()
    c.set_seed()
    _, _, x_te, y_te, dataset = c.load_data()
    n_test = min(args.n_test, len(x_te))
    x_te, y_te = x_te[:n_test], y_te[:n_test]

    checkpoints = {
        "clean": "evasion_clean_model.pth",
        "robust": "robust_model.pth",
    }
    selected = list(checkpoints) if args.model == "both" else [args.model]
    model_results = {
        name: evaluate_model(name, checkpoints[name], x_te, y_te, args)
        for name in selected
    }
    results: Dict[str, object] = {
        "dataset": dataset,
        "n_test": n_test,
        "seed": c.SEED,
        "settings": {
            "pgd_norm": "Linf",
            "pgd_eps": args.pgd_eps,
            "pgd_eps_step": args.pgd_eps / 4,
            "pgd_max_iter": 20,
            "cw_norm": "L2",
            "cw_confidence": 0.0,
            "cw_learning_rate": args.cw_learning_rate,
            "cw_initial_const": args.cw_initial_const,
            "cw_binary_search_steps": args.cw_binary_steps,
            "cw_max_iter": args.cw_max_iter,
            "cw_batch_size": args.cw_batch_size,
        },
        "models": model_results,
    }
    json_path = c.save_json("cw_vs_pgd_results.json", results)
    md_path = write_markdown(results)
    chart_path = write_chart(results)
    print(f"\nSaved: {json_path}\nSaved: {md_path}")
    if chart_path:
        print(f"Saved: {chart_path}")


if __name__ == "__main__":
    main()
