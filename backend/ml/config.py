from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "ml" / "models"

CSV_NAME = "phishing_email.csv"

URL_TOKEN = "<URL>"

DECISION_THRESHOLD = 0.4088

TFIDF_PARAMS = {
    "max_features": 20_000,
    "ngram_range": (1, 2),
    "stop_words": "english",
    "strip_accents": "unicode",
}

LR_PARAMS = {
    "class_weight": "balanced",
    "max_iter": 1_000,
    "random_state": 42,
}

TEST_SIZE = 0.2
RANDOM_STATE = 42

EVAL_REPORT_PATH = MODEL_DIR / "eval_report.txt"
