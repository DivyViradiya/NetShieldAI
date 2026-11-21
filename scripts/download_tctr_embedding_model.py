#!/usr/bin/env python3
"""
NetShieldAI — TCTR Embedding Model Downloader & Packager (Item 1.2 — P1)
Downloads BAAI/bge-m3 locally to NetShieldAI/models/TCTR/embedding_model
for offline, air-gapped operation.
"""

import os
import sys
import shutil
from pathlib import Path

# Resolve base directories
SCRIPT_DIR = Path(__file__).resolve().parent
NETSHIELD_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = NETSHIELD_DIR.parent if (NETSHIELD_DIR.parent / "NetShieldAI").exists() else NETSHIELD_DIR

TARGET_DIR = NETSHIELD_DIR / "models" / "TCTR" / "embedding_model"
CUSTOM_CACHE_DIR = PROJECT_ROOT / ".cache" / "huggingface"

# Override HF_HOME to avoid permission errors on root-owned ~/.cache/huggingface
os.environ["HF_HOME"] = str(CUSTOM_CACHE_DIR)
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

MODEL_NAME = "BAAI/bge-m3"

def main():
    print("=" * 70)
    print(" NetShieldAI — TCTR Embedding Model Downloader (BAAI/bge-m3)")
    print("=" * 70)
    print(f"[*] Target Directory: {TARGET_DIR}")
    print(f"[*] HuggingFace Cache Directory: {CUSTOM_CACHE_DIR}")
    print(f"[*] Model Identifier: {MODEL_NAME}")
    print("-" * 70)

    CUSTOM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    try:
        from sentence_transformers import SentenceTransformer
        import torch
        import numpy as np
    except ImportError as e:
        print(f"[!] Error: Missing required dependencies: {e}")
        print("    Please run inside virtual environment: source .venv/bin/activate")
        sys.exit(1)

    device = "mps" if torch.backends.mps.is_available() else ("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Detected Compute Device: {device.upper()}")

    print(f"\n[1/3] Downloading {MODEL_NAME} weights from Hugging Face...")
    print("      (This is ~1.1 GB - 2.2 GB; download speed depends on your network)...")
    try:
        model = SentenceTransformer(
            MODEL_NAME,
            device=device,
            cache_folder=str(CUSTOM_CACHE_DIR)
        )
        print("[+] Download complete!")
    except Exception as e:
        print(f"[!] Failed to download model: {e}")
        sys.exit(1)

    print(f"\n[2/3] Saving offline model package to: {TARGET_DIR}...")
    try:
        model.save(str(TARGET_DIR))
        print("[+] Offline weights saved successfully!")
    except Exception as e:
        print(f"[!] Failed to save model to target directory: {e}")
        sys.exit(1)

    print(f"\n[3/3] Verifying offline standalone loading...")
    try:
        # Test loading directly from the target folder
        loaded_model = SentenceTransformer(str(TARGET_DIR), device=device)
        test_text = "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        test_emb = loaded_model.encode([test_text], convert_to_numpy=True, normalize_embeddings=True)
        
        dim = test_emb.shape[1]
        print(f"[+] Model loaded from local disk!")
        print(f"[+] Output Embedding Dimension: {dim} (Expected: 1024)")
        
        if dim == 1024:
            print("[+] Dimension verification: PASSED")
        else:
            print(f"[!] Warning: Unexpected dimension {dim} (expected 1024)")

        # Zero-shot similarity quick check
        test_query = "User login input is concatenated directly into SQL statement"
        query_emb = loaded_model.encode([test_query], convert_to_numpy=True, normalize_embeddings=True)
        similarity = float(np.dot(test_emb[0], query_emb[0]))
        print(f"[+] Zero-Shot Verification (SQLi similarity): {similarity:.4f} (Expected > 0.70)")
        
        if similarity >= 0.70:
            print("[+] Semantic similarity check: PASSED")
        else:
            print(f"[!] Warning: Similarity lower than expected: {similarity:.4f}")

    except Exception as e:
        print(f"[!] Verification failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print(" [SUCCESS] BAAI/bge-m3 is packaged and ready for offline production use!")
    print(f" Location: {TARGET_DIR}")
    print("=" * 70)

if __name__ == "__main__":
    main()
