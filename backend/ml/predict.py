import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from ml.config import MODEL_DIR
from ml.preprocess import clean_text


class PhishingClassifier:
    """Loaded model + vectorizer + threshold, ready for inference."""

    def __init__(self, model_dir: Path = MODEL_DIR):
        for fname in ["tfidf_vectorizer.pkl", "lr_model.pkl", "threshold.pkl"]:
            if not (model_dir / fname).exists():
                raise FileNotFoundError(
                    f"{fname} not found in {model_dir}. "
                    f"Run train_pipeline.py first."
                )
            
        self.vectorizer: TfidfVectorizer = joblib.load(model_dir / "tfidf_vectorizer.pkl")
        self.model: LogisticRegression = joblib.load(model_dir / "lr_model.pkl")
        self.threshold: float = joblib.load(model_dir / "threshold.pkl")["threshold"]

    def predict_proba(self, text: str) -> float:
        """Return phishing probability (0–1) for a single email text."""
        cleaned = clean_text(text)
        vec = self.vectorizer.transform([cleaned])
        return float(self.model.predict_proba(vec)[0, 1])

    def predict(self, text: str) -> tuple[int, float]:
        """Return (prediction, probability) where prediction is 0 (legitimate) or 1 (phishing)."""
        proba = self.predict_proba(text)
        pred = int(proba >= self.threshold)
        return pred, proba
