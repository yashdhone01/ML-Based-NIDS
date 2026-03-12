# ML-Based Network Intrusion Detection Engine

![Python](https://img.shields.io/badge/Python-3.10-blue)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.4-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-99.96%25-brightgreen)

## What is it?

A modular ML engine that classifies network traffic as **Normal, DoS, Probe, R2L, or U2R**. Unlike rule-based tools like Snort, it learns attack patterns from data — no hand-written rules, no manual updates.

Scoped intentionally as an engine only. Plug it into any pipeline, retrain on any dataset.

## Usage
```bash
git clone https://github.com/yashdhone01/ML-Based-NIDS.git
cd ML-Based-NIDS

python -m venv venv
venv\Scripts\activate     # Windows
source venv/bin/activate  # Mac/Linux

pip install -r requirements.txt
python -m src.train       # downloads KDD99 + trains model
python example.py         # run predictions
```
```python
from src.predict import NIDSEngine

engine = NIDSEngine()
result = engine.predict({'src_bytes': 491, 'dst_bytes': 0, 'count': 2})
# {'prediction': 'DoS', 'confidence': 0.98, 'status': 'alert'}

results = engine.predict_batch([record1, record2, ...])
```

## Results

| Model | Accuracy |
|---|---|
| Logistic Regression | 98.60% |
| Decision Tree | 99.95% |
| **Random Forest** | **99.96%** |

Trained on the full KDD Cup 99 dataset (494K records) — not the common 10% subset. This matters most for **U2R** (privilege escalation), where class imbalance is extreme (52 samples vs 391K DoS). Most approaches score 40–60% recall on U2R. This engine hits **80%**.
```
              precision    recall  f1-score   support

         DoS       1.00      1.00      1.00     78292
      Normal       1.00      1.00      1.00     19456
       Probe       0.97      0.98      0.97       822
         R2L       0.98      0.97      0.98       225
         U2R       1.00      0.80      0.89        10
```

## Project Structure
```
├── src/
│   ├── preprocess.py   # data pipeline
│   ├── train.py        # train & save model
│   └── predict.py      # NIDSEngine class
├── models/             # gitignored .pkl files
├── example.py
└── requirements.txt
```

## Why not rule-based?

Rule-based systems need a new rule for every new attack. Attackers who slightly modify known techniques slip through. This engine generalises from patterns — a modified attack still looks like an attack.

## Feedback

Working on adversarial robustness, live packet integration, or want to test on CICIDS2017 or NSL-KDD? Open an issue or find me on [Twitter](https://x.com/Yash354642) · [Portfolio](https://yashdhone.vercel.app)