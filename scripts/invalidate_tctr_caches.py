#!/usr/bin/env python3
"""
NetShieldAI — Invalidate Legacy TCTR Vector Caches (Item 1.2 — P1)
Purges outdated 384-dimensional .npy embedding caches that are incompatible
with the new 1024-dimensional BAAI/bge-m3 embedding model.
"""

import os
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "Data"
CACHE_DIR = DATA_DIR / "embeddings_cache"
TCTR_FEATURES_DIR = DATA_DIR / "TCTR_features"

def main():
    print("=" * 70)
    print(" NetShieldAI — Legacy TCTR Cache Invalidation")
    print("=" * 70)
    
    total_freed_bytes = 0
    removed_files = 0
    
    if CACHE_DIR.exists():
        for file in CACHE_DIR.glob("*.npy"):
            size = file.stat().st_size
            file.unlink()
            total_freed_bytes += size
            removed_files += 1
        print(f"[+] Purged {removed_files} legacy 384-d batch files from {CACHE_DIR}")
    else:
        print(f"[*] Cache directory {CACHE_DIR} does not exist.")

    freed_mb = total_freed_bytes / (1024 * 1024)
    print(f"[+] Total disk space freed: {freed_mb:.2f} MB")
    print("=" * 70)
    print(" [SUCCESS] Legacy embedding caches invalidated.")
    print("=" * 70)

if __name__ == "__main__":
    main()
