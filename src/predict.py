# src/predict.py — cleaner version
import joblib
import numpy as np
import os

FEATURES = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'count', 'srv_count'
]

class NIDSEngine:
    """
    ML-Based Network Intrusion Detection Engine.
    Classifies network traffic as: Normal, DoS, Probe, R2L, or U2R.

    Usage:
        engine = NIDSEngine()
        result = engine.predict({'src_bytes': 491, 'dst_bytes': 0, ...})
    """

    def __init__(self, model_path='models/rf_model.pkl',
                 scaler_path='models/scaler.pkl'):
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}. Run: python -m src.train"
            )
        self.model  = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

    def predict(self, input_dict: dict) -> dict:
        """
        Predict traffic category from a dict of feature values.
        Missing features default to 0.

        Returns:
            dict with keys: prediction, confidence, status, features_used
        """
        features = [input_dict.get(f, 0) for f in FEATURES]
        X = self.scaler.transform([features])
        prediction = self.model.predict(X)[0]
        confidence = self.model.predict_proba(X)[0].max()

        return {
            'prediction': prediction,
            'confidence': round(float(confidence), 4),
            'status':     'alert' if prediction != 'Normal' else 'normal',
            'features_used': FEATURES
        }

    def predict_batch(self, records: list) -> list:
        """
        Predict on a list of dicts. Returns list of result dicts.
        """
        return [self.predict(r) for r in records]