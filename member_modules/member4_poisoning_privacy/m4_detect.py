"""
Thành viên 4 - Các kỹ thuật phát hiện mẫu backdoor trên lớp biểu diễn đặc trưng (fc1).
Chỉ dùng numpy + scikit-learn (không cần torch) để dễ kiểm thử.

  - Activation Clustering (Chen et al., 2018): với mỗi lớp, giảm chiều (PCA) rồi phân 2 cụm k-means;
    nếu hai cụm tách bạch (silhouette cao bất thường so với các lớp khác) thì loại cụm nhỏ hơn.
  - Spectral Signatures (Tran et al., 2018): với mỗi lớp, trừ trung bình, lấy vector kỳ dị trái-phải đầu tiên;
    điểm bất thường = (chiếu lên vector đó)^2; loại q% mẫu có điểm cao nhất mỗi lớp.
"""
import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics import adjusted_rand_score, roc_auc_score, silhouette_score

AC_PCA_DIM = 10
AC_MIN_MARGIN = 0.05   # silhouette của lớp phải vượt trung vị các lớp ít nhất ngần này (và 2.5 MAD)


def _cluster_class(feats_c, seed):
    k = max(2, min(AC_PCA_DIM, feats_c.shape[1], len(feats_c) - 1))
    Z = PCA(n_components=k, random_state=seed).fit_transform(feats_c)
    km = KMeans(n_clusters=2, n_init=10, random_state=seed).fit(Z)
    lab = km.labels_
    sil = float(silhouette_score(Z, lab)) if len(np.unique(lab)) == 2 else 0.0
    return lab, sil


def activation_clustering(feats, y, seed=0, is_poison=None, n_classes=10):
    """
    Trả về (flagged_size, flagged_oracle, info).
      flagged_size   : loại CỤM NHỎ HƠN trong các lớp bị nghi ngờ (quy tắc gốc của bài báo, không cần nhãn thật).
      flagged_oracle : loại CỤM CÓ NHIỀU MẪU ĐỘC HƠN trong các lớp bị nghi ngờ (cần nhãn thật => chỉ là CẬN TRÊN,
                       mô phỏng một chuyên gia xem ảnh trung bình của từng cụm rồi chọn đúng cụm).
    Lớp bị nghi ngờ = lớp có silhouette 2 cụm cao bất thường so với các lớp còn lại.
    """
    flagged_size = np.zeros(len(y), dtype=bool)
    flagged_oracle = np.zeros(len(y), dtype=bool) if is_poison is not None else None
    clusters, sils = {}, np.zeros(n_classes)
    for c in range(n_classes):
        idx = np.where(y == c)[0]
        lab, sil = _cluster_class(feats[idx], seed)
        clusters[c] = (idx, lab)
        sils[c] = sil
    med = float(np.median(sils))
    mad = float(np.median(np.abs(sils - med)) * 1.4826)
    thr = med + max(2.5 * mad, AC_MIN_MARGIN)
    flagged_classes = [c for c in range(n_classes) if sils[c] > thr]
    for c in flagged_classes:
        idx, lab = clusters[c]
        small = int(np.argmin(np.bincount(lab, minlength=2)))
        flagged_size[idx[lab == small]] = True
        if is_poison is not None:
            fr = [is_poison[idx][lab == k].mean() if (lab == k).any() else 0.0 for k in (0, 1)]
            flagged_oracle[idx[lab == int(np.argmax(fr))]] = True
    info = {"silhouettes": [float(s) for s in sils], "threshold": thr,
            "flagged_classes": flagged_classes, "clusters": clusters}
    return flagged_size, flagged_oracle, info


def spectral_scores(feats_c):
    X = feats_c - feats_c.mean(axis=0, keepdims=True)
    _, _, vt = np.linalg.svd(X, full_matrices=False)
    return (X @ vt[0]) ** 2


def spectral_signatures(feats, y, q, n_classes=10):
    """Loại q (0-1) mẫu có điểm phổ cao nhất trong MỖI lớp."""
    flagged = np.zeros(len(y), dtype=bool)
    for c in range(n_classes):
        idx = np.where(y == c)[0]
        k = int(round(q * len(idx)))
        if k > 0:
            order = np.argsort(-spectral_scores(feats[idx]))[:k]
            flagged[idx[order]] = True
    return flagged


def class_diagnostics(feats, y, is_poison, target, info, seed=0):
    """
    Chẩn đoán trong lớp mục tiêu (dùng nhãn thật để ĐÁNH GIÁ, người kiểm toán không biết):
      auc_isolation_forest / auc_spectral : AUROC của điểm bất thường trong lớp mục tiêu (0.5 = vô dụng)
      ari / poison_frac_in_clusters : mức độ k-means 2 cụm khớp với mẫu độc
    """
    idx = np.where(y == target)[0]
    p = is_poison[idx].astype(int)
    out = {"n_class": int(len(idx)), "poison_frac_in_class": float(p.mean())}
    if p.min() == p.max():
        return out
    iso = IsolationForest(n_estimators=200, random_state=seed).fit(feats[idx])
    out["auc_isolation_forest"] = float(roc_auc_score(p, -iso.score_samples(feats[idx])))
    out["auc_spectral"] = float(roc_auc_score(p, spectral_scores(feats[idx])))
    _, lab = info["clusters"][target]
    out["ari"] = float(adjusted_rand_score(p, lab))
    out["poison_frac_in_clusters"] = [float(p[lab == k].mean()) if (lab == k).any() else 0.0 for k in (0, 1)]
    out["cluster_sizes"] = [int((lab == k).sum()) for k in (0, 1)]
    out["silhouette_target"] = info["silhouettes"][target]
    others = [s for c, s in enumerate(info["silhouettes"]) if c != target]
    out["silhouette_median_others"] = float(np.median(others))
    return out