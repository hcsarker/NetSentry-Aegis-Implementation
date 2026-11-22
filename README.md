# NetSentry-Aegis: Reference Implementation & Benchmark Suite

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Framework: Zero--Trust](https://img.shields.io/badge/Architecture-Zero--Trust%20NIST%20SP%20800--207-green.svg)](https://csrc.nist.gov/publications/detail/sp/800-207/final)

This repository contains the complete reference implementation, empirical benchmark suite, and artifact generation scripts for the research paper:

> **"NetSentry-Aegis: An AI-Driven Zero-Trust Cyber Defense Framework for Intelligent IoT and Edge Networks"**  
> *Authors: Md. Hridoy Joarder, Dr. Md. Sobuz Mia*  
> *Department of Computer Science and Engineering, Patuakhali Science and Technology University (PSTU)*

NetSentry-Aegis operationalizes the Zero-Trust mandate of *"never trust implicitly, continuously verify"* directly on resource-constrained edge gateways. It pairs lightweight machine-learning threat inference with an asymmetric dynamic trust engine and a 6-tier graduated network policy enforcement layer.

---

## 📑 Table of Contents
1. [Key Features](#-key-features)
2. [Multi-Dataset Benchmark Results](#-multi-dataset-benchmark-results)
3. [Repository Structure](#-repository-structure)
4. [Prerequisites & Installation](#-prerequisites--installation)
5. [End-to-End Execution Guide](#-end-to-end-execution-guide)
6. [Dynamic Trust Engine & Enforcement Mapping](#-dynamic-trust-engine--enforcement-mapping)
7. [Paper Artifacts](#-paper-artifacts)
8. [Citation & License](#-citation--license)

---

## 🚀 Key Features

* **Sub-Millisecond Edge Inference:** XGBoost executes in **0.21 ms per sample** with a serialized model binary of only **241 KB**, leaving a memory footprint of `<48 MB` on ARM edge boards.
* **Mathematical Asymmetric Dynamic Trust Engine:** Employs an Asymmetric Exponentially Weighted Moving Average (EWMA) recursion ($\eta_{down} = 0.50$ vs. $\eta_{up} = 0.15$). Hostile nodes are quarantined within 3–4 malicious connections, while recovery requires at least 10 consecutive verified clean flows, defeating trust-flapping and intermittent evasions.
* **6-Tier Graduated Enforcement:** Eliminates binary alert drop pitfalls by mapping trust scores into: `Allow` ($\ge 80$), `Monitor` ($60-79$), `Re-authenticate` ($40-59$), `Restrict` ($25-39$), `Isolate` ($10-24$), and `Block` ($<10$). Validated with Linux `iptables`, Traffic Control (`tc`) bandwidth throttling, and OpenFlow SDN rules.
* **Cross-Benchmark Evaluation:** Evaluated across **5 major datasets** (~400,000+ real network flows) spanning enterprise traffic, botnet captures, and smart-home IoT devices.
* **Leakage-Free Cross-Validation:** Built using strict in-fold scaling pipelines to eliminate train-test feature leakage.

---

## 📊 Multi-Dataset Benchmark Results

The following table summarizes the measured detection performance of the NetSentry-Aegis detection engine (XGBoost) across all evaluated benchmarks:

| Benchmark Dataset | Domain Profile | Test Samples | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Latency (ms) |
|---|---|---|---|---|---|---|---|---|
| **NSL-KDD** | Zero-Day Distribution Shift | 22,544 | 79.7% | 96.8% | 66.5% | **0.789** | 0.971 | 0.206 ms |
| **UNSW-NB15** | Modern Hybrid Enterprise | 175,341 | 90.1% | 98.9% | 86.4% | **0.922** | 0.986 | 0.006 ms |
| **CICIDS2017** | Multi-Vector Enterprise | 14,166 | 99.8% | 99.7% | 99.9% | **0.998** | 1.000 | 0.197 ms |
| **N-BaIoT** | Real IoT Botnet (Danmini Doorbell) | 22,500 | 99.9% | 99.9% | 99.9% | **0.999** | 1.000 | 0.001 ms |
| **CICIOT2023** | Smart Home IoT Mesh Traffic | 15,000 | 99.5% | 99.7% | 99.8% | **0.997** | 0.999 | 0.001 ms |

---

## 📂 Repository Structure

```
NetSentry-Aegis-Implementation/
├── code/
│   ├── 01_preprocess.py             # Feature encoding & standardization
│   ├── 02_train_models.py           # Trains RF, XGBoost, LogReg, Autoencoder
│   ├── 03_trust_engine.py           # Asymmetric EWMA scoring & policy simulation
│   ├── 04_generate_figures.py       # Generates primary paper figures (Figs 1–10)
│   ├── 05_cross_validation.py       # Strict in-fold 5-fold cross-validation
│   ├── 06_cicids_validation.py      # Replication on CICIDS2017 benchmark
│   ├── 07_adversarial_test.py       # Black-box perturbation sweep
│   ├── 08_generate_extra_figures.py # Additional verification figures (Figs 11–13)
│   ├── 09_validation_probs.py       # Grouped out-of-fold validation proxies
│   ├── 10_adversarial_strong.py     # Targeted query-based evasion study
│   ├── 11_policy_comparison.py      # Comparative policy analysis vs. baselines
│   ├── 12_data_checks.py            # Zero-day recall diagnostics
│   ├── 13_seed_variability.py       # Multi-seed stability profiling
│   ├── 14_final_figures.py          # Final figure generation script
│   ├── run_multi_dataset.py         # Multi-dataset benchmarking (UNSW, N-BaIoT, CICIOT)
│   ├── build_final_docx.py          # Formatted Word manuscript generator
│   └── demo_enforcement_gateway.py  # Practical Linux iptables & tc enforcement
├── figs/                            # High-resolution paper charts and architecture diagrams
├── outputs/                         # Exported JSON metrics, logs, and roc curves
├── results/                         # Pre-computed reference evaluation metrics
├── paper/
│   ├── NetSentry-Aegis_FINAL_Publishable_Manuscript.md # Full journal manuscript
│   └── NetSentry-Aegis_Journal_Manuscript_Final.docx   # Publication-ready Word document
├── download_data.py                 # Automated benchmark dataset downloader
├── run_all.py                       # Single-command pipeline executor
├── LICENSE                          # MIT License
└── README.md                        # This documentation file
```

---

## 💻 Prerequisites & Installation

### 1. System Requirements
* Python 3.10 or higher
* Standard CPU (GPU acceleration is entirely optional; all models train in minutes on standard commodity processors).

### 2. Setup Environment
```bash
# Clone the repository
git clone -b HCS https://github.com/hcsarker/NetSentry-Aegis-Implementation.git
cd NetSentry-Aegis-Implementation

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install required dependencies
pip install numpy pandas scikit-learn xgboost matplotlib joblib python-docx
```

---

## ⚡ End-to-End Execution Guide

### Step 1: Download Primary Datasets
```bash
python download_data.py
```

### Step 2: Run Core Model Training & Trust Simulation
```bash
# Run data preprocessing, model training, trust engine, and figure generation
python run_all.py
```

### Step 3: Run Multi-Dataset IoT Benchmark Suite
```bash
python code/run_multi_dataset.py
```

### Step 4: Generate Publication-Ready Word (.docx) Manuscript
```bash
python code/build_final_docx.py
```
*Outputs: `paper/NetSentry-Aegis_Journal_Manuscript_Final.docx` (complete with embedded figures and tables).*

---

## 🛡️ Dynamic Trust Engine & Enforcement Mapping

The trust score $T_t \in [0, 100]$ dynamically updates per flow according to:

$$Target_t^* = \alpha_t \cdot (1 - p_t) \times 100$$

$$T_t = \Pi_{[0, 100]} \Big( (1 - \eta_t) T_{t-1} + \eta_t \cdot Target_t^* \Big)$$

$$\eta_t = \begin{cases} 0.50, & \text{if } Target_t^* < T_{t-1} \text{ (Hostile behavior)} \\ 0.15, & \text{if } Target_t^* \ge T_{t-1} \text{ (Normal recovery)} \end{cases}$$

| Tier | Trust Range | Access Policy | Linux Gateway Realization (`iptables` / `tc`) |
|---|---|---|---|
| **Allow** | $80 \le T \le 100$ | Unrestricted normal routing | `iptables -A FORWARD -s <IP> -j ACCEPT` |
| **Monitor** | $60 \le T < 80$ | Normal routing + mirrored logging | `iptables -A FORWARD -s <IP> -j LOG --log-prefix "[AEGIS] "` |
| **Re-auth** | $40 \le T < 60$ | Redirect HTTP/CoAP to auth portal | `iptables -t nat -A PREROUTING -s <IP> -p tcp --dport 80 -j DNAT ...` |
| **Restrict** | $25 \le T < 40$ | Rate-limit to 64 kbps, drop ports $>1024$ | `tc class change ... rate 64kbit` |
| **Isolate** | $10 \le T < 25$ | Quarantine VLAN (Diagnostic server only) | `iptables -A FORWARD -s <IP> -d ! <SOC_IP> -j DROP` |
| **Block** | $0 \le T < 10$ | Total packet drop | `iptables -I FORWARD 1 -s <IP> -j DROP` |

---

## 📜 Paper Artifacts

* **Full Journal Manuscript (Markdown):** [`paper/NetSentry-Aegis_FINAL_Publishable_Manuscript.md`](paper/NetSentry-Aegis_FINAL_Publishable_Manuscript.md)
* **Formatted Journal Document (Word):** [`paper/NetSentry-Aegis_Journal_Manuscript_Final.docx`](paper/NetSentry-Aegis_Journal_Manuscript_Final.docx)
* **Supervisor Action Plan & Rebuttal Guide:** [`SUPERVISOR_FEEDBACK_ANALYSIS_AND_ACTION_PLAN.md`](SUPERVISOR_FEEDBACK_ANALYSIS_AND_ACTION_PLAN.md)
* **Bangla Complete Project Guide:** [`NETSENTRY_AEGIS_FULL_EXPLANATION_BN.md`](NETSENTRY_AEGIS_FULL_EXPLANATION_BN.md)

---

## ⚖️ Citation & License

This project is licensed under the terms of the [MIT License](LICENSE).

If you use this reference implementation, code, or benchmark data in your academic work, please cite:

```bibtex
@article{joarder2026netsentry,
  title={NetSentry-Aegis: An AI-Driven Zero-Trust Cyber Defense Framework for Intelligent IoT and Edge Networks},
  author={Joarder, Md. Hridoy and Mia, Md. Sobuz},
  journal={Preprint / Under Review},
  year={2026}
}
```
