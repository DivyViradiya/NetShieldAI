### Table 1 — TCTR Engineered Feature Vector (10-Dimensional)

| Feature | Category | Description | Rank | SHAP Gain |
|---|---|---|---|---|
| `mock_threat_velocity` | Temporal | EPSS / Δt — exploit weaponization speed proxy | 1 | 1842.3 |
| `semantic_centrality` | Graph | KNN-graph degree centrality in embedding space | 2 | 1204.7 |
| `mock_threat_acceleration` | Temporal | Rate of change of threat velocity (2nd derivative) | 3 | 987.1 |
| `days_since_pub_at_horizon` | Temporal | Age of CVE relative to query horizon | 4 | 754.6 |
| `base_score` | Severity | CVSS base score static anchor | 5 | 631.2 |
| `desc_length` | Linguistic | Character count — proxy for semantic richness | 6 | 489.5 |
| `days_to_last_modify` | Temporal | Days to last NVD update (patch / exploit activity) | 7 | 412.8 |
| `num_affected_products` | Structural | Count of vulnerable software packages / versions | 8 | 378.3 |
| `num_keywords` | Linguistic | Exploit-related term density in name + description | 9 | 295.4 |
| `num_platforms` | Structural | Cross-platform breadth (OS / hardware coverage) | 10 | 211.9 |
