# Độ chính xác theo epsilon - trước/sau phòng thủ (MNIST)

Số mẫu kiểm thử: 1000. Độ chính xác sạch: trước = 98.5%, sau = 96.2%.

| Tấn công | epsilon | Trước phòng thủ | Sau phòng thủ | Phục hồi (điểm %) |
|---|---|---|---|---|
| FGSM | 0.05 | 92.9% | 95.8% | +2.9 |
| FGSM | 0.1 | 72.9% | 94.1% | +21.2 |
| FGSM | 0.2 | 16.4% | 88.9% | +72.5 |
| FGSM | 0.3 | 3.5% | 79.7% | +76.2 |
| PGD | 0.05 | 91.8% | 95.6% | +3.8 |
| PGD | 0.1 | 63.1% | 93.4% | +30.3 |
| PGD | 0.2 | 4.1% | 85.0% | +80.9 |
| PGD | 0.3 | 0.7% | 68.6% | +67.9 |
