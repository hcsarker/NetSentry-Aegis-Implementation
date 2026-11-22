"""
run_all.py
-----------
Executes the complete NetSentry-Aegis pipeline end-to-end:
1. Preprocessing (01_preprocess.py)
2. Training & Evaluating 4 Models (02_train_models.py)
3. Dynamic Trust Engine & Zero-Trust Enforcement (03_trust_engine.py)
4. Primary Figures Generation (04_generate_figures.py)
5. 5-Fold Cross Validation (05_cross_validation.py)
6. CICIDS2017 Dataset Replication (06_cicids_validation.py)
7. Adversarial Perturbation Evasion Test (07_adversarial_test.py)
8. Robustness Figures Generation (08_generate_extra_figures.py)
"""

import os
import subprocess
import sys
import time
import warnings

warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"

SCRIPTS = [
    ("01_preprocess.py", "Data Preprocessing & Scaling (NSL-KDD)"),
    ("02_train_models.py", "Model Training (RF, XGBoost, LogReg, Autoencoder)"),
    ("03_trust_engine.py", "Dynamic Trust Scoring & Zero-Trust Enforcement Simulation"),
    ("04_generate_figures.py", "Generating Primary Figures (Fig 4 to Fig 10)"),
    ("05_cross_validation.py", "5-Fold Cross Validation (Internal Robustness Check)"),
    ("06_cicids_validation.py", "Second Dataset Validation (CICIDS2017 Benchmark)"),
    ("07_adversarial_test.py", "Adversarial Noise Evasion Sweep against XGBoost"),
    ("08_generate_extra_figures.py", "Generating Robustness Figures (Fig 11 to Fig 13)"),
]

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    code_dir = os.path.join(base_dir, "code")
    data_dir = os.path.join(base_dir, "data")

    # Check if data directory has required files
    kdd_train = os.path.join(data_dir, "KDDTrain.txt")
    kdd_test = os.path.join(data_dir, "KDDTest.txt")
    cicids = os.path.join(data_dir, "CICIDS2017_sample.csv")

    if not (os.path.exists(kdd_train) and os.path.exists(kdd_test)):
        print("[!] Datasets not found in 'data/' folder.")
        print("[*] Running 'download_data.py' automatically first...")
        subprocess.run([sys.executable, os.path.join(base_dir, "download_data.py")], check=True)

    total_start = time.time()
    print("\n" + "=" * 70)
    print("   NetSentry-Aegis Complete End-to-End Pipeline Execution")
    print("=" * 70 + "\n")

    for i, (script_name, description) in enumerate(SCRIPTS, 1):
        script_path = os.path.join(code_dir, script_name)
        print(f"\n[{i}/{len(SCRIPTS)}] RUNNING: {script_name} - {description}")
        print("-" * 70)
        
        start_time = time.time()
        ret = subprocess.run([sys.executable, script_path])
        elapsed = time.time() - start_time
        
        if ret.returncode != 0:
            print(f"\n[ERROR] Step {script_name} failed with exit code {ret.returncode}!")
            sys.exit(ret.returncode)
        
        print(f"[COMPLETED] {script_name} in {elapsed:.2f} seconds.")

    total_time = time.time() - total_start
    print("\n" + "=" * 70)
    print(f"[SUCCESS] All 8 scripts completed successfully in {total_time:.2f} seconds ({total_time / 60:.1f} mins)!")
    print("Outputs stored in: outputs/")
    print("Figures saved in:  figs/")
    print("=" * 70)

if __name__ == "__main__":
    main()

