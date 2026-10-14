"""
Tiện ích dùng chung cho các script của Thành viên 4 (Data Poisoning & Privacy).

Nội dung:
  - nạp dữ liệu MNIST (có phương án dự phòng nếu không tải được)
  - tạo trigger cho backdoor
  - huấn luyện mô hình SimpleCNN (cùng kiến trúc với target_systems/classifier)
  - huấn luyện kiểu DP-SGD (cắt gradient từng mẫu + thêm nhiễu Gaussian)
  - tấn công Membership Inference dựa trên loss
"""
import os
import sys
import json
import random

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../.."))
if ROOT not in sys.path:
    sys.path.append(ROOT)

from shared_logging.audit_logger import log_result  # noqa: E402,F401

# Dùng đúng kiến trúc của hệ thống mục tiêu (Target 1).
try:
    from target_systems.classifier.train import SimpleCNN  # noqa: E402
except Exception:  # dự phòng: định nghĩa lại cùng kiến trúc
    class SimpleCNN(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv1 = nn.Conv2d(1, 10, kernel_size=5)
            self.conv2 = nn.Conv2d(10, 20, kernel_size=5)
            self.fc1 = nn.Linear(320, 50)
            self.fc2 = nn.Linear(50, 10)

        def forward(self, x):
            x = F.relu(F.max_pool2d(self.conv1(x), 2))
            x = F.relu(F.max_pool2d(self.conv2(x), 2))
            x = x.view(-1, 320)
            x = F.relu(self.fc1(x))
            x = self.fc2(x)
            return F.log_softmax(x, dim=1)


class DropoutCNN(SimpleCNN):
    """SimpleCNN có thêm Dropout - dùng làm biện pháp phòng thủ quyền riêng tư."""

    def __init__(self, p=0.5):
        super().__init__()
        self.p = p

    def forward(self, x):
        x = F.relu(F.max_pool2d(self.conv1(x), 2))
        x = F.relu(F.max_pool2d(self.conv2(x), 2))
        x = x.view(-1, 320)
        x = F.relu(self.fc1(x))
        x = F.dropout(x, p=self.p, training=self.training)
        x = self.fc2(x)
        return F.log_softmax(x, dim=1)


DATA_DIR = os.path.join(HERE, "data")
RESULTS_DIR = os.path.join(HERE, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

TARGET_CLASS = 7  # lớp mà kẻ tấn công muốn ép mô hình dự đoán

# ---- Cấu hình thực nghiệm (chỉnh ở đây, mọi script sẽ dùng chung) ----
N_TRAIN = 10000          # số mẫu huấn luyện dùng cho thí nghiệm poisoning
N_TEST = 2000            # số mẫu kiểm thử
EPOCHS = 5               # số epoch huấn luyện
SEEDS = [0, 1, 2]        # chạy nhiều seed rồi lấy trung bình
POISON_RATES = [0.005, 0.01, 0.02, 0.05]   # tỉ lệ mẫu độc / toàn bộ tập huấn luyện
HEADLINE_RATE = 0.05     # mức nhiễm độc dùng làm số liệu chính ghi vào audit_results.json
HEADLINE_MODE = "adversarial"   # kiểu mẫu độc dùng làm số liệu chính ("plain" hoặc "adversarial")
PGD_EPS = 0.3            # biên độ nhiễu đối kháng L-inf cho mẫu độc (thang pixel 0-1)
PGD_STEPS = 10           # số bước PGD


# --------------------------------------------------------------------------
# Tiện ích chung
# --------------------------------------------------------------------------
def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def save_json(name, obj):
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    return path


def load_json(name):
    path = os.path.join(RESULTS_DIR, name)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Chưa có {path}. Hãy chạy script tương ứng trước (xem thứ tự trong README)."
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------
# Dữ liệu
# --------------------------------------------------------------------------
def load_data(n_train=None, n_test=None, seed=0):
    """
    Trả về (Xtr, ytr, Xte, yte, tên_dataset).
    X có dạng float32 [N, 1, 28, 28], giá trị trong [0, 1].
    """
    try:
        from torchvision import datasets

        tr = datasets.MNIST(DATA_DIR, train=True, download=True)
        te = datasets.MNIST(DATA_DIR, train=False, download=True)
        Xtr = tr.data.float().div(255.0).unsqueeze(1)
        ytr = tr.targets.clone().long()
        Xte = te.data.float().div(255.0).unsqueeze(1)
        yte = te.targets.clone().long()
        name = "MNIST"
    except Exception as e:  # không tải được -> dùng bộ digits của scikit-learn
        print(f"[CẢNH BÁO] Không nạp được MNIST ({type(e).__name__}). "
              f"Dùng sklearn digits (8x8 phóng lên 28x28) thay thế.")
        from sklearn.datasets import load_digits

        d = load_digits()
        X = torch.tensor(d.images / 16.0, dtype=torch.float32).unsqueeze(1)
        X = F.interpolate(X, size=28, mode="bilinear", align_corners=False)
        y = torch.tensor(d.target, dtype=torch.long)
        g = torch.Generator().manual_seed(1234)
        perm = torch.randperm(len(X), generator=g)
        cut = int(0.7 * len(X))
        Xtr, ytr = X[perm[:cut]], y[perm[:cut]]
        Xte, yte = X[perm[cut:]], y[perm[cut:]]
        name = "sklearn-digits (phóng lên 28x28)"

    g = torch.Generator().manual_seed(seed)
    if n_train is not None and n_train < len(Xtr):
        idx = torch.randperm(len(Xtr), generator=g)[:n_train]
        Xtr, ytr = Xtr[idx], ytr[idx]
    if n_test is not None and n_test < len(Xte):
        idx = torch.randperm(len(Xte), generator=g)[:n_test]
        Xte, yte = Xte[idx], yte[idx]
    return Xtr, ytr, Xte, yte, name


def load_trusted_clean(n=2000, seed=0):
    """
    Tập dữ liệu SẠCH đáng tin cậy (người kiểm toán tự thu thập), KHÔNG giao với tập huấn luyện
    N_TRAIN mẫu mà load_data() chọn (cùng seed => cùng hoán vị, lấy phần đứng sau N_TRAIN).
    """
    Xfull, yfull, _, _, _ = load_data(None, None, seed=seed)
    g = torch.Generator().manual_seed(seed)
    perm = torch.randperm(len(Xfull), generator=g)
    idx = perm[N_TRAIN:N_TRAIN + n]
    return Xfull[idx], yfull[idx]


# --------------------------------------------------------------------------
# Backdoor: trigger và tập huấn luyện bị đầu độc
# --------------------------------------------------------------------------
def add_trigger(x, size=6, margin=1, value=1.0):
    """Gắn ô vuông sáng size x size ở góc dưới bên phải của ảnh."""
    x = x.clone()
    x[..., -(size + margin):-margin, -(size + margin):-margin] = value
    return x


def make_hard_carriers(surrogate, X, y, eps=PGD_EPS, steps=PGD_STEPS):
    """
    Làm cho mẫu độc 'khó học bằng đặc trưng tự nhiên' (kỹ thuật clean-label kiểu label-consistent):
    dùng PGD để TĂNG loss của ảnh trên một mô hình thay thế (surrogate). Nhãn vẫn đúng,
    nhưng mô hình nạn nhân không thể dựa vào nét chữ để phân loại nên buộc phải dựa vào trigger.
    """
    surrogate.eval()
    alpha = 2.5 * eps / steps
    x_adv = X.clone()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.nll_loss(surrogate(x_adv), y)
        (grad_x,) = torch.autograd.grad(loss, x_adv)
        x_adv = x_adv.detach() + alpha * grad_x.sign()
        x_adv = torch.min(torch.max(x_adv, X - eps), X + eps).clamp(0.0, 1.0)
    return x_adv.detach()


def make_poisoned_train(Xtr, ytr, poison_rate, target=TARGET_CLASS, seed=0,
                        mode="plain", surrogate=None):
    """
    Clean-label backdoor: chỉ gắn trigger vào ảnh THUỘC LỚP MỤC TIÊU và GIỮ NGUYÊN NHÃN,
    nên người rà soát thủ công khó phát hiện (nhãn vẫn đúng).
      mode="plain"       : chỉ gắn trigger.
      mode="adversarial" : trước khi gắn trigger, làm nhiễu đối kháng ảnh (PGD) để ảnh khó học.
    poison_rate = số mẫu độc / tổng số mẫu huấn luyện.
    Trả về (X_độc, y, mask_độc).
    """
    rng = np.random.RandomState(seed)
    idx_target = np.where(ytr.numpy() == target)[0]
    n_poison = min(int(round(poison_rate * len(ytr))), len(idx_target))
    mask = torch.zeros(len(ytr), dtype=torch.bool)
    Xp = Xtr.clone()
    if n_poison > 0:
        chosen = rng.choice(idx_target, n_poison, replace=False)
        mask[torch.tensor(chosen)] = True
        carriers = Xtr[mask]
        if mode == "adversarial":
            if surrogate is None:  # kẻ tấn công tự huấn luyện mô hình thay thế
                surrogate = train_model(SimpleCNN(), Xtr, ytr, epochs=EPOCHS, seed=seed + 100)
            carriers = make_hard_carriers(surrogate, carriers, ytr[mask])
        Xp[mask] = add_trigger(carriers)
    return Xp, ytr.clone(), mask


# --------------------------------------------------------------------------
# Huấn luyện / đánh giá
# --------------------------------------------------------------------------
def train_model(model, X, y, epochs=5, lr=0.05, momentum=0.9, weight_decay=0.0,
                batch_size=64, seed=0):
    set_seed(seed)
    opt = torch.optim.SGD(model.parameters(), lr=lr, momentum=momentum,
                          weight_decay=weight_decay)
    g = torch.Generator().manual_seed(seed)
    n = len(X)
    model.train()
    for _ in range(epochs):
        perm = torch.randperm(n, generator=g)
        for i in range(0, n, batch_size):
            idx = perm[i:i + batch_size]
            opt.zero_grad()
            loss = F.nll_loss(model(X[idx]), y[idx])
            loss.backward()
            opt.step()
    model.eval()
    return model


def train_model_dp(model, X, y, epochs=5, lr=0.1, batch_size=64, clip_norm=1.0,
                   noise_multiplier=1.0, seed=0):
    """
    Huấn luyện kiểu DP-SGD: (1) tính gradient TỪNG MẪU, (2) cắt chuẩn về clip_norm,
    (3) cộng nhiễu Gaussian N(0, (noise_multiplier*clip_norm)^2) vào tổng, (4) lấy trung bình.
    Lưu ý: bản này KHÔNG tính ngân sách riêng tư epsilon chính thức (cần thư viện như Opacus).
    """
    from torch.func import functional_call, vmap, grad

    set_seed(seed)
    gen = torch.Generator().manual_seed(seed)
    params = {k: v.detach().clone() for k, v in model.named_parameters()}

    def loss_fn(p, xb, yb):
        out = functional_call(model, p, (xb.unsqueeze(0),))
        return F.nll_loss(out, yb.unsqueeze(0))

    per_sample_grad = vmap(grad(loss_fn), in_dims=(None, 0, 0))

    model.train()
    n = len(X)
    for _ in range(epochs):
        perm = torch.randperm(n, generator=gen)
        for i in range(0, n, batch_size):
            idx = perm[i:i + batch_size]
            xb, yb = X[idx], y[idx]
            b = len(idx)
            g = per_sample_grad(params, xb, yb)
            sq = sum((g[k].reshape(b, -1) ** 2).sum(dim=1) for k in g)
            factor = (clip_norm / (sq.sqrt() + 1e-6)).clamp(max=1.0)
            for k in params:
                shape = [b] + [1] * (g[k].dim() - 1)
                summed = (g[k] * factor.view(*shape)).sum(dim=0)
                noise = torch.randn(summed.shape, generator=gen) * noise_multiplier * clip_norm
                params[k] = params[k] - lr * (summed + noise) / b
    with torch.no_grad():
        for k, p in model.named_parameters():
            p.copy_(params[k])
    model.eval()
    return model


@torch.no_grad()
def predict_logprob(model, X, bs=1000):
    model.eval()
    return torch.cat([model(X[i:i + bs]) for i in range(0, len(X), bs)])


def accuracy(model, X, y):
    return (predict_logprob(model, X).argmax(1) == y).float().mean().item()


def attack_success_rate(model, Xte, yte, target=TARGET_CLASS):
    """ASR: tỉ lệ ảnh KHÔNG thuộc lớp mục tiêu, sau khi gắn trigger, bị phân loại thành lớp mục tiêu."""
    mask = yte != target
    pred = predict_logprob(model, add_trigger(Xte[mask])).argmax(1)
    return (pred == target).float().mean().item()


@torch.no_grad()
def penultimate_features(model, X, bs=1000):
    """Đặc trưng lớp ẩn fc1 (50 chiều) - dùng cho Isolation Forest."""
    model.eval()
    outs = []
    for i in range(0, len(X), bs):
        x = X[i:i + bs]
        x = F.relu(F.max_pool2d(model.conv1(x), 2))
        x = F.relu(F.max_pool2d(model.conv2(x), 2))
        x = x.view(-1, 320)
        outs.append(F.relu(model.fc1(x)))
    return torch.cat(outs).numpy()


# --------------------------------------------------------------------------
# Membership Inference Attack (dựa trên loss)
# --------------------------------------------------------------------------
@torch.no_grad()
def per_sample_loss(model, X, y):
    return F.nll_loss(predict_logprob(model, X), y, reduction="none").numpy()


def mia_loss_attack(model, Xm, ym, Xn, yn, seed=0):
    """
    Tấn công ngưỡng-loss: mẫu có loss thấp => nhiều khả năng là thành viên (đã dùng để huấn luyện).
    Chia đôi dữ liệu: nửa 1 để chọn ngưỡng, nửa 2 để đánh giá (tập cân bằng => đoán mò = 50%).
    Trả về dict {mia_accuracy, mia_auc}.
    """
    from sklearn.metrics import roc_auc_score

    lm = per_sample_loss(model, Xm, ym)
    ln = per_sample_loss(model, Xn, yn)
    rng = np.random.RandomState(seed)
    k = min(len(lm), len(ln))
    lm = lm[rng.permutation(len(lm))[:k]]
    ln = ln[rng.permutation(len(ln))[:k]]
    h = k // 2
    lm_fit, lm_ev = lm[:h], lm[h:]
    ln_fit, ln_ev = ln[:h], ln[h:]

    # chọn ngưỡng tối ưu trên nửa 1
    cands = np.unique(np.concatenate([lm_fit, ln_fit]))
    best_t, best_acc = cands[0], 0.0
    for t in cands:
        acc = 0.5 * ((lm_fit <= t).mean() + (ln_fit > t).mean())
        if acc > best_acc:
            best_acc, best_t = acc, t

    acc = 0.5 * ((lm_ev <= best_t).mean() + (ln_ev > best_t).mean())
    y_true = np.concatenate([np.ones(len(lm_ev)), np.zeros(len(ln_ev))])
    score = -np.concatenate([lm_ev, ln_ev])
    auc = roc_auc_score(y_true, score)
    return {"mia_accuracy": float(acc), "mia_auc": float(auc)}


# --------------------------------------------------------------------------
# Thí nghiệm MIA dùng chung cho assess_privacy_mia.py và defense_privacy.py
# --------------------------------------------------------------------------
MIA_N_MEMBERS = 500        # số mẫu dùng để huấn luyện mô hình mục tiêu (tập thành viên)
MIA_EPOCHS = 60            # huấn luyện lâu, không regularization => mô hình dễ ghi nhớ dữ liệu
MIA_SEEDS = [0, 1, 2, 3, 4]


def run_mia_trial(Xtr, ytr, Xte, yte, seed, defense="none", dropout_p=0.5, weight_decay=5e-3,
                  sigma=1.0, clip_norm=1.0):
    """
    Một lần thí nghiệm MIA:
      - thành viên     : MIA_N_MEMBERS mẫu lấy ngẫu nhiên từ tập huấn luyện (mô hình được huấn luyện trên chúng)
      - không thành viên: MIA_N_MEMBERS mẫu đầu tiên của tập kiểm thử (mô hình chưa từng thấy)
      - độ chính xác kiểm thử (utility): phần còn lại của tập kiểm thử
    defense: "none" | "dropout" (Dropout + weight decay) | "dp" (DP-SGD tự cài đặt, nhiễu sigma)
    """
    rng = np.random.RandomState(seed)
    mem_idx = torch.tensor(rng.choice(len(Xtr), MIA_N_MEMBERS, replace=False))
    Xm, ym = Xtr[mem_idx], ytr[mem_idx]
    Xn, yn = Xte[:MIA_N_MEMBERS], yte[:MIA_N_MEMBERS]
    Xt, yt = Xte[MIA_N_MEMBERS:], yte[MIA_N_MEMBERS:]

    if defense == "none":
        model = train_model(SimpleCNN(), Xm, ym, epochs=MIA_EPOCHS, seed=seed)
    elif defense == "dropout":
        model = train_model(DropoutCNN(dropout_p), Xm, ym, epochs=MIA_EPOCHS,
                            weight_decay=weight_decay, seed=seed)
    elif defense == "dp":
        model = train_model_dp(SimpleCNN(), Xm, ym, epochs=MIA_EPOCHS, noise_multiplier=sigma,
                               clip_norm=clip_norm, seed=seed)
    else:
        raise ValueError(defense)

    res = mia_loss_attack(model, Xm, ym, Xn, yn, seed=seed)
    res["train_acc"] = accuracy(model, Xm, ym)
    res["test_acc"] = accuracy(model, Xt, yt)
    return res


def mean_over(trials, key):
    return float(np.mean([t[key] for t in trials]))