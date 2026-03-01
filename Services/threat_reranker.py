import os
import json
import logging
import numpy as np
import joblib
from pathlib import Path
from datetime import datetime

# Set up a fallback logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
# Navigate up to project root, then to models/TCTR
MODELS_DIR = BASE_DIR.parent / "models" / "TCTR"

LGB_MODEL_PATH = MODELS_DIR / "lgb_ranker.pkl"

# Global instances for lazy loading
_ranker = None
_sentence_model = None

def _load_models():
    """Lazily loads the LightGBM Ranker and Sentence Transformer."""
    global _ranker, _sentence_model
    if _ranker is None:
        try:
            if LGB_MODEL_PATH.exists():
                logger.info(f"Loading TCTR LightGBM Ranker from {LGB_MODEL_PATH}...")
                _ranker = joblib.load(LGB_MODEL_PATH)
                logger.info("LightGBM Ranker loaded successfully.")
            else:
                logger.error(f"LightGBM Ranker not found at {LGB_MODEL_PATH}. Using fallback scoring.")
            
            # Load Sentence Transformer (used for future semantic similarity or GAT integration)
            try:
                from sentence_transformers import SentenceTransformer
                logger.info("Loading Sentence Transformer (all-MiniLM-L6-v2)...")
                _sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
            except ImportError:
                logger.warning("sentence_transformers not installed. NLP features disabled.")
                
        except Exception as e:
            logger.error(f"Failed to load TCTR components: {e}")
            # Don't raise, allowing fallback scoring logic to function

def extract_features(name: str, description: str, severity_score: float = 5.0) -> np.ndarray:
    """
    Extracts the 10 features expected by the TCTR LightGBM model.
    1. desc_length
    2. num_keywords
    3. num_platforms
    4. num_affected_products
    5. days_since_pub_at_horizon
    6. days_to_last_modify
    7. mock_threat_velocity
    8. mock_threat_acceleration
    9. semantic_centrality
    10. base_severity_score
    """
    desc = description if description else ""
    
    desc_length = len(desc)
    # Estimate keywords by name words + unique long words in desc
    num_keywords = len(name.split()) + min(len([w for w in desc.split() if len(w) > 5]), 15)
    
    # Static proxies for real-time discoveries
    num_platforms = 1
    num_affected_products = 1
    
    # Temporal features (for live finding, assume age of 1 day to prevent log(0))
    days_since_pub = 1.0
    days_to_modify = 1.0
    
    # Velocity/Acceleration derived from severity proxy (0-10)
    # In training, velocity = epss / age. Here we use base_score as epss proxy.
    velocity = severity_score / days_since_pub
    acceleration = velocity / days_since_pub
    
    # Create feature names to match training
    feature_names = [
        "desc_length", "num_keywords", "num_platforms", "num_affected_products",
        "days_since_pub_at_horizon", "days_to_last_modify", "mock_threat_velocity",
        "mock_threat_acceleration", "semantic_centrality", "base_severity_score"
    ]
    
    # Static fallback for missing features in real-time scoring
    days_to_last_modify = days_to_modify # Use the alias defined above
    semantic_centrality = 0.0
    
    features_raw = [
        float(desc_length), float(num_keywords), float(num_platforms), float(num_affected_products),
        float(days_since_pub), float(days_to_modify), float(velocity),
        float(acceleration), float(semantic_centrality), float(severity_score)
    ]
    
    try:
        import pandas as pd
        return pd.DataFrame([features_raw], columns=feature_names)
    except ImportError:
        return np.array([features_raw])

def predict_threat_risk(finding_name: str, description: str = "", severity: str = "Medium") -> float:
    """
    Main prediction entry point. 
    Returns a score normalized to [0, 1] reflecting predicted risk priority.
    """
    try:
        _load_models()
    except:
        pass
        
    # Map qualitative severity to quantitative base score (0-10)
    severity_map = {
        "Critical": 9.5,
        "High": 8.0,
        "Medium": 5.0,
        "Low": 2.5,
        "Info": 1.0,
        "Informational": 1.0
    }
    base_score = severity_map.get(severity, 5.0)
    
    features = extract_features(finding_name, description, severity_score=base_score)
    
    try:
        if _ranker:
            # Predict raw rank score from LambdaMART
            # If features is a DataFrame, LightGBM will use feature names
            raw_score = _ranker.predict(features)[0]
            
            # Normalize to [0, 1]. In training, relevance was [0, 4].
            final_score = np.clip(raw_score / 4.0, 0.05, 0.99)
            return round(float(final_score), 4)
    except Exception as e:
        logger.error(f"Ranking inference failed for {finding_name}: {e}")
        # Log the shape for debugging
        if hasattr(features, 'shape'):
            logger.error(f"Feature shape: {features.shape}")
    
    # Fallback to normalized baseline score
    return round(base_score / 10.0, 4)

def predict_risk(finding_name: str, description: str = "") -> float:
    """Legacy alias for backward compatibility."""
    return predict_threat_risk(finding_name, description)

def rerank_findings(findings: list) -> list:
    """
    Central utility to process a list of findings from any scanner.
    Enriches with re-ranking scores and sorts by priority.
    """
    if not findings:
        return []
        
    for f in findings:
        # Normalize keys across different scanners
        name = f.get('name') or f.get('service') or f.get('title') or f.get('check_id') or "Unknown Finding"
        desc = (f.get('description') or f.get('vulnerability_notes') or f.get('message') or 
                f"{f.get('type','')} {f.get('payload','')}".strip() or "")
        sev = f.get('risk') or f.get('severity') or "Medium"
        
        # Inject predicted score
        f['predicted_risk_score'] = predict_threat_risk(name, desc, sev)
        
    # Sort descending by predicted score
    return sorted(findings, key=lambda x: x.get('predicted_risk_score', 0), reverse=True)
