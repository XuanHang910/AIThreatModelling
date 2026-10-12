import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as c  

import torch 

TRAIN_EPS = c.HEADLINE_EPS   # mức nhiễu dùng khi huấn luyện đối kháng
DEFENSE_EPOCHS = c.EPOCHS  # cùng số epoch với mô hình gốc để so sánh công bằng


def run_defense():
    print("Training robust model...")
    try:
        before = c.load_json("evasion_results.json")
    except FileNotFoundError:
        sys.exit("Chưa có results/evasion_results.json - hãy chạy assess_evasion.py trước.")

    c.set_seed()
    x_tr, y_tr, x_te, y_te, dataset = c.load_data()
    if dataset != before["dataset"]:
        print(f"[WARN] Dataset khác lần tấn công ({before['dataset']} vs {dataset}); "
              "hãy chạy lại assess_evasion.py để so sánh công bằng.")

    from art.attacks.evasion import ProjectedGradientDescent
    from art.defences.trainer import AdversarialTrainer

    model = c.SimpleCNN()
    clf = c.make_classifier(model)
    train_attack = ProjectedGradientDescent(
        clf, eps=TRAIN_EPS, eps_step=TRAIN_EPS / 4, max_iter=10,
        num_random_init=1, batch_size=c.BATCH, verbose=False)
    trainer = AdversarialTrainer(clf, attacks=train_attack, ratio=0.5)
    print(f"Adversarial training: PGD eps={TRAIN_EPS}, ratio=0.5, epochs={DEFENSE_EPOCHS}")
    trainer.fit(x_tr, __import__("numpy").eye(10, dtype="float32")[y_tr],
                nb_epochs=DEFENSE_EPOCHS, batch_size=c.BATCH)
    model.eval()
    torch.save(model.state_dict(), os.path.join(c.HERE, "robust_model.pth"))

    robust_clf = c.make_classifier(model)
    clean_acc = c.accuracy(model, x_te, y_te)
    after = {"dataset": dataset, "train_eps": TRAIN_EPS, "epochs": DEFENSE_EPOCHS,
             "clean_accuracy": clean_acc, "fgsm": {}, "pgd": {}}
    c.log_result("member2_defense", "robust_clean_accuracy", clean_acc, {"dataset": dataset})

    for kind in ("fgsm", "pgd"):
        for eps in c.EPSILONS:
            acc, _ = c.accuracy_under_attack(robust_clf, x_te, y_te, kind, eps)
            after[kind][str(eps)] = acc
            c.log_result("member2_defense", f"accuracy_{kind}_eps_{eps}_after_defense", acc,
                         {"dataset": dataset})

    # Số liệu tiêu đề: độ chính xác dưới PGD ở eps lớn nhất, sau phòng thủ.
    headline = after["pgd"][str(c.HEADLINE_EPS)]
    c.log_result("member2_defense", "robust_accuracy", headline,
                 {"attack": "pgd", "eps": c.HEADLINE_EPS, "dataset": dataset,
                  "before_defense": before["pgd"][str(c.HEADLINE_EPS)]})

    c.save_json("defense_results.json", after)
    write_table_and_chart(before, after)


def write_table_and_chart(before, after):
    lines = [
        f"# Độ chính xác theo epsilon - trước/sau phòng thủ ({after['dataset']})",
        "",
        f"Số mẫu kiểm thử: {before['n_test']}. Độ chính xác sạch: "
        f"trước = {before['clean_accuracy']:.1%}, sau = {after['clean_accuracy']:.1%}.",
        "",
        "| Tấn công | epsilon | Trước phòng thủ | Sau phòng thủ | Phục hồi (điểm %) |",
        "|---|---|---|---|---|",
    ]
    for kind in ("fgsm", "pgd"):
        for eps in c.EPSILONS:
            b, a = before[kind][str(eps)], after[kind][str(eps)]
            lines.append(f"| {kind.upper()} | {eps} | {b:.1%} | {a:.1%} | {100 * (a - b):+.1f} |")
    path = os.path.join(c.RESULTS_DIR, "comparison_table.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"Saved: {path}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        xs = [0.0] + c.EPSILONS
        fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
        for ax, kind in zip(axes, ("fgsm", "pgd")):
            yb = [before["clean_accuracy"]] + [before[kind][str(e)] for e in c.EPSILONS]
            ya = [after["clean_accuracy"]] + [after[kind][str(e)] for e in c.EPSILONS]
            ax.plot(xs, yb, "o-", color="#c0392b", label="Trước phòng thủ")
            ax.plot(xs, ya, "s-", color="#2471a3", label="Sau adversarial training")
            ax.set_title(kind.upper())
            ax.set_xlabel("epsilon (L-inf)")
            ax.set_ylim(0, 1.02)
            ax.grid(alpha=0.3)
        axes[0].set_ylabel("Độ chính xác")
        axes[0].legend()
        fig.tight_layout()
        out = os.path.join(c.RESULTS_DIR, "accuracy_vs_epsilon.png")
        fig.savefig(out, dpi=150)
        print(f"Saved: {out}")
    except Exception as exc:
        print(f"[WARN] Không vẽ được biểu đồ: {exc}")


if __name__ == "__main__":
    run_defense()
