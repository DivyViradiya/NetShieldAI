### Table 2 — TCTR Framework Evaluation Leaderboard (Out-of-Time Test Set)

| Model Architecture | NDCG@10 | AUC-ROC | AUC-PR | MAP@10 | ↑ vs. Naive |
|---|---|---|---|---|---|
| CVSS Static Ordering (Naive Baseline) | 0.5183 | 0.4821 | 0.3914 | 0.4207 | — |
| XGBoost Classifier (Tabular Baseline) | 0.6291 | 0.5322 | 0.4485 | 0.5109 | +21.4% |
| Graph Attention Network — ThreatGAT | 0.6064 | 0.4992 | 0.4121 | 0.4919 | +17.0% |
| **★ LightGBM LambdaMART (TCTR Engine)** | **0.6960** | — | — | — | **+34.3%** |
