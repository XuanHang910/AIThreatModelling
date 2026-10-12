import json
import os
import random
import sys

import numpy as np
import torch
import torch.nn as nn

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../"))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from shared_logging.audit_logger import LOG_FILE, log_result  # noqa: E402
from target_systems.classifier.train import SimpleCNN  # noqa: E402

RESULTS_DIR = os.path.join(HERE, "results")

# Các mức nhiễu epsilon (chuẩn L-inf, ảnh chuẩn hóa về [0, 1]).
EPSILONS = [0.05, 0.1, 0.2, 0.3]
HEADLINE_EPS = 0.3  # mức epsilon dùng làm số liệu tiêu đề trong báo cáo

SEED = 42
N_TRAIN = int(os.environ.get("M2_N_TRAIN", 10000))
N_TEST = int(os.environ.get("M2_N_TEST", 1000))
EPOCHS = int(os.environ.get("M2_EPOCHS", 20))
BATCH = 128


def set_seed(seed: int = SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_data():
    """Trả về (X_train, y_train, X_test, y_test, tên_dataset).

    X có dạng (N, 1, 28, 28), float32 trong [0, 1] - đúng đầu vào của SimpleCNN.
    """
    try:
        from torchvision import datasets

        root = os.path.join(HERE, "data")
        tr = datasets.MNIST(root, train=True, download=True)
        te = datasets.MNIST(root, train=False, download=True)
        x_tr = tr.data.numpy().astype("float32")[:, None] / 255.0
        y_tr = tr.targets.numpy().astype("int64")
        x_te = te.data.numpy().astype("float32")[:, None] / 255.0
        y_te = te.targets.numpy().astype("int64")
        name = "MNIST"
    except Exception as exc:  # không có mạng / bị chặn
        print(f"[WARN] Không tải được MNIST ({type(exc).__name__}). "
              "Dùng sklearn-digits (resize 28x28) làm dự phòng.")
        import torch.nn.functional as F
        from sklearn.datasets import load_digits
        from sklearn.model_selection import train_test_split

        d = load_digits()
        x = torch.tensor(d.images, dtype=torch.float32)[:, None] / 16.0
        x = F.interpolate(x, size=(28, 28), mode="bilinear", align_corners=False)
        x = x.clamp(0, 1).numpy()
        y = d.target.astype("int64")
        x_tr, x_te, y_tr, y_te = train_test_split(
            x, y, test_size=0.2, random_state=SEED, stratify=y)
        name = "sklearn-digits (fallback)"

    rng = np.random.RandomState(SEED)
    i_tr = rng.permutation(len(x_tr))[:N_TRAIN]
    i_te = rng.permutation(len(x_te))[:N_TEST]
    return x_tr[i_tr], y_tr[i_tr], x_te[i_te], y_te[i_te], name


# huấn luyện / đo
def train_model(model, x, y, epochs: int = EPOCHS, lr: float = 1e-3):
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.NLLLoss()
    xt, yt = torch.tensor(x), torch.tensor(y)
    model.train()
    for ep in range(epochs):
        perm = torch.randperm(len(xt))
        total = 0.0
        for i in range(0, len(xt), BATCH):
            idx = perm[i:i + BATCH]
            opt.zero_grad()
            loss = loss_fn(model(xt[idx]), yt[idx])
            loss.backward()
            opt.step()
            total += loss.item() * len(idx)
        print(f"  epoch {ep + 1}/{epochs}  loss={total / len(xt):.4f}")
    model.eval()
    return model


def accuracy(model, x, y) -> float:
    model.eval()
    with torch.no_grad():
        preds = []
        for i in range(0, len(x), 512):
            preds.append(model(torch.tensor(x[i:i + 512])).argmax(1).numpy())
    return float((np.concatenate(preds) == y).mean())


#  IBM ART
def make_classifier(model):
    from art.estimators.classification import PyTorchClassifier

    return PyTorchClassifier(
        model=model,
        loss=nn.NLLLoss(),  # SimpleCNN trả về log_softmax
        optimizer=torch.optim.Adam(model.parameters(), lr=1e-3),
        input_shape=(1, 28, 28),
        nb_classes=10,
        clip_values=(0.0, 1.0),
    )


def make_attack(classifier, kind: str, eps: float):
    from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent

    if kind == "fgsm":
        return FastGradientMethod(classifier, eps=eps, batch_size=BATCH)
    if kind == "pgd":
        return ProjectedGradientDescent(
            classifier, eps=eps, eps_step=eps / 4, max_iter=20,
            num_random_init=1, batch_size=BATCH, verbose=False)
    raise ValueError(kind)


def accuracy_under_attack(classifier, x, y, kind: str, eps: float):
    """Độ chính xác trên ảnh đối kháng + nhiễu L-inf lớn nhất thực tế."""
    x_adv = make_attack(classifier, kind, eps).generate(x=x)
    preds = classifier.predict(x_adv).argmax(1)
    max_linf = float(np.abs(x_adv - x).max())
    return float((preds == y).mean()), max_linf


#  lưu / log
def save_json(name: str, obj) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    return path


def load_json(name: str):
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def reset_logs(*modules: str) -> None:
    """Xóa các dòng log cũ (kể cả số liệu giả) trong shared_logging/audit_results.json để chạy lại không bị trùng."""
    if not os.path.exists(LOG_FILE):
        return
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except Exception:
        return
    logs = [e for e in logs if e.get("module") not in modules]
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4)


__all__ = [
    "SimpleCNN", "log_result", "EPSILONS", "HEADLINE_EPS", "SEED", "EPOCHS",
    "set_seed", "load_data", "train_model", "accuracy", "make_classifier",
    "make_attack", "accuracy_under_attack", "save_json", "load_json",
    "reset_logs", "RESULTS_DIR", "HERE",
]
