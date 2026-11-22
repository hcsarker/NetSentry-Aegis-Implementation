"""
download_data.py
-----------------
Automated data downloader for the NetSentry-Aegis framework.
Works on Windows, Linux, and macOS without requiring curl, wget, or unzip.
Uses Python's standard library (urllib + zipfile).
"""

import os
import sys
import urllib.request
import zipfile
import io

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

URLS = {
    "KDDTrain.txt": "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt",
    "KDDTest.txt": "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt",
}

CICIDS_ZIP_URL = "https://codeload.github.com/NirmalaKTomar/CICIDS2017_Sample_dataset/zip/refs/heads/main"


def download_file(url, target_path):
    print(f"[*] Downloading {os.path.basename(target_path)} from:\n    {url} ...")
    def reporthook(block_num, block_size, total_size):
        if total_size > 0:
            percent = block_num * block_size * 100 / total_size
            sys.stdout.write(f"\r    Progress: {percent:5.1f}% [{block_num * block_size // 1024} KB / {total_size // 1024} KB]")
            sys.stdout.flush()
    urllib.request.urlretrieve(url, target_path, reporthook)
    print("\n[+] Done.")


def download_cicids(target_csv_path):
    print(f"[*] Downloading CICIDS2017 Sample dataset from:\n    {CICIDS_ZIP_URL} ...")
    req = urllib.request.Request(
        CICIDS_ZIP_URL, 
        headers={'User-Agent': 'Mozilla/5.0'}
    )
    with urllib.request.urlopen(req) as resp:
        zip_bytes = resp.read()
    
    print("[*] Extracting CICIDS2017_sample.csv from zip archive...")
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        # Find the sample file in the zip
        sample_name = None
        for name in z.namelist():
            if name.endswith("CICIDS2017_sample.csv"):
                sample_name = name
                break
        
        if not sample_name:
            raise FileNotFoundError("CICIDS2017_sample.csv not found inside downloaded archive!")
        
        with z.open(sample_name) as source, open(target_csv_path, "wb") as target:
            target.write(source.read())
            
    print(f"[+] Saved to: {target_csv_path}")


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"Target data directory: {DATA_DIR}\n")

    # 1. NSL-KDD Files
    for filename, url in URLS.items():
        path = os.path.join(DATA_DIR, filename)
        if os.path.exists(path) and os.path.getsize(path) > 1000:
            print(f"[=] {filename} already exists. Skipping download.")
        else:
            download_file(url, path)

    # 2. CICIDS2017 Sample
    cicids_path = os.path.join(DATA_DIR, "CICIDS2017_sample.csv")
    if os.path.exists(cicids_path) and os.path.getsize(cicids_path) > 1000:
        print("[=] CICIDS2017_sample.csv already exists. Skipping download.")
    else:
        download_cicids(cicids_path)

    print("\n[SUCCESS] All datasets are ready in the 'data/' directory!")


if __name__ == "__main__":
    main()

