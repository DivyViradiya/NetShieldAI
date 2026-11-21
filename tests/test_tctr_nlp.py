import os
import sys
from pathlib import Path

# Add NetShieldAI to path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    import pytest
except ImportError:
    pytest = None

import numpy as np
from Services.tctr_engine import get_engine, TCTREngine

def get_test_engine():
    """Initializes and returns the singleton TCTREngine instance."""
    return get_engine()

if pytest is not None:
    @pytest.fixture(scope="module")
    def engine():
        return get_test_engine()

def test_model_loaded_and_dimension(engine):
    """Verifies that the embedding model is loaded with dimension 1024."""
    assert engine._sentence_model is not None, "SentenceTransformer model failed to load"
    assert engine._cwe_text_embeddings is not None, "CWE reference embeddings not precomputed"
    
    # Verify embedding dimension is 1024 (BAAI/bge-m3)
    dim = engine._cwe_text_embeddings.shape[1]
    assert dim == 1024, f"Expected embedding dimension 1024, got {dim}"

def test_zero_shot_cwe_inferences(engine):
    """Tests zero-shot inference for real-world unmapped vulnerability findings."""
    test_cases = [
        ("SQL Injection", "User input is concatenated directly into SQL statement: SELECT * FROM users WHERE id=", "89"),
        ("Cross-Site Scripting", "Stored JavaScript executes in browser when viewing user comments: <script>alert(1)</script>", "79"),
        ("OS Command Execution", "Parameter passed directly to popen shell command: ping -c 1; id", "78"),
        ("Directory Traversal", "Arbitrary file disclosure via ../../../../etc/passwd in file download handler", "22"),
        ("Cleartext Transmission", "Unencrypted HTTP login sends passwords across network in cleartext", "319"),
        ("Arbitrary File Upload", "Attacker can upload shell.php without content-type verification", "434"),
        ("Missing CSRF Token", "Money transfer POST request lacks validation for anti-CSRF token", "352"),
        ("Weak Cryptography", "Web server supports deprecated SSLv3 and weak RC4 ciphers", "310"),
        ("Broken Authentication", "Missing password validation allows administrative login without credentials", "287"),
        ("Buffer Overflow", "Unchecked memcpy length causes stack buffer overflow in packet processing", "119"),
    ]

    for name, description, expected_cwe in test_cases:
        matched = engine._infer_cwe(name, description)
        assert matched == expected_cwe, f"Expected CWE-{expected_cwe} for '{name}', but got CWE-{matched}"

def test_benign_text_rejection(engine):
    """Verifies that benign/unrelated text does not trigger a false positive CWE match."""
    benign_text = "HTTP 200 OK - Homepage rendered normally with status code 200"
    matched = engine._infer_cwe("Homepage Status", benign_text)
    assert matched is None, f"Expected None for benign input, but got CWE-{matched}"

def test_predict_risk_integration(engine):
    """Tests the full predict_risk pipeline with LightGBM and BGE-M3."""
    res = engine.predict_risk(
        name="Unknown SQL Syntax Error",
        description="Database returned error: quoted string not terminated at character 42",
        cwe_id=None
    )
    
    assert "score" in res
    assert "tctr_priority" in res
    assert "priority_level" in res
    assert "risk_justification" in res
    
    assert 0.0 <= res["score"] <= 1.0
    assert 0.0 <= res["tctr_priority"] <= 10.0
    assert res["priority_level"] in ["P0 (Critical)", "P1 (High)", "P2 (Medium)", "P3 (Low)"]
    assert res["base_score"] >= 9.0  # Matched to SQLi (9.8)

if __name__ == "__main__":
    import sys
    print("Running TCTR BGE-M3 test suite...")
    eng = get_engine()
    
    test_model_loaded_and_dimension(eng)
    print("[PASS] test_model_loaded_and_dimension passed (dim=1024)")
    
    test_zero_shot_cwe_inferences(eng)
    print("[PASS] test_zero_shot_cwe_inferences passed (10/10 CWE matches)")
    
    test_benign_text_rejection(eng)
    print("[PASS] test_benign_text_rejection passed")
    
    test_predict_risk_integration(eng)
    print("[PASS] test_predict_risk_integration passed")
    
    print("\nALL TCTR NLP TESTS PASSED SUCCESSFULLY!")
