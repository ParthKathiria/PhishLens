import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)

from ml.config import (
    TFIDF_PARAMS,
    LR_PARAMS,
    TEST_SIZE,
    RANDOM_STATE,
    DECISION_THRESHOLD,
    MODEL_DIR,
    EVAL_REPORT_PATH,
)
from ml.load_data import load_phishing_data
from ml.preprocess import preprocess


def main():
    print("=" * 60)
    print("PhishLens — TF-IDF + Logistic Regression Pipeline")
    print("=" * 60)

    # ── Load ──
    print("\n[1/5] Loading dataset...")
    df = load_phishing_data()

    # ── Preprocess ──
    print("[2/5] Preprocessing text...")
    df = preprocess(df)
    X = df["text"].to_numpy()
    y = df["label"].to_numpy()

    # ── Split ──
    print("[3/5] Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    print(f"    Train: {len(X_train)}  Test: {len(X_test)}")

    # ── Vectorize ──
    print("[4/5] Fitting TF-IDF vectorizer...")
    vectorizer = TfidfVectorizer(**TFIDF_PARAMS)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"    Vocabulary size: {len(vectorizer.vocabulary_)}")

    # ── Train ──
    print("[5/5] Training Logistic Regression...")
    model = LogisticRegression(**LR_PARAMS)
    model.fit(X_train_vec, y_train)

    # ── Evaluate ──
    print(f"\nDecision threshold: {DECISION_THRESHOLD}")
    print("\n" + "=" * 60)
    print("Evaluation")
    print("=" * 60)

    test_proba = model.predict_proba(X_test_vec)[:, 1]
    y_test_pred = (test_proba >= DECISION_THRESHOLD).astype(int)

    report = classification_report(y_test, y_test_pred,
                                   target_names=["Legitimate", "Phishing"])
    cm = confusion_matrix(y_test, y_test_pred)
    auc = roc_auc_score(y_test, test_proba)

    print(report)
    print(f"ROC-AUC: {auc:.4f}\n")
    print("Confusion Matrix:")
    print(f"              Predicted")
    print(f"              Legit  Phish")
    print(f"Actual Legit  {cm[0,0]:>5} {cm[0,1]:>5}")
    print(f"       Phish  {cm[1,0]:>5} {cm[1,1]:>5}")
    print()

    fn = cm[1, 0]
    fp = cm[0, 1]
    print(f"False negatives (missed phishing): {fn}")
    print(f"False positives (wrongly flagged): {fp}")

    # ── Save report ──
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    lines = [
        "=" * 60,
        "PhishLens — Evaluation Report",
        "=" * 60,
        f"Dataset: phishing_email.csv",
        f"Samples: {len(df)} ({y.sum()} phishing, {(y == 0).sum()} legitimate)",
        f"Split: {len(X_train)} train / {len(X_test)} test",
        f"Decision threshold: {DECISION_THRESHOLD}",
        f"TF-IDF params: {TFIDF_PARAMS}",
        f"LR params: {LR_PARAMS}",
        "",
        "Classification Report:",
        report,
        f"ROC-AUC: {auc:.4f}",
        "",
        "Confusion Matrix:",
        f"              Predicted",
        f"              Legit  Phish",
        f"Actual Legit  {cm[0,0]:>5} {cm[0,1]:>5}",
        f"       Phish  {cm[1,0]:>5} {cm[1,1]:>5}",
        "",
        f"False negatives (missed phishing): {fn}",
        f"False positives (wrongly flagged): {fp}",
    ]
    EVAL_REPORT_PATH.write_text("\n".join(lines))
    print(f"\nEvaluation report saved to {EVAL_REPORT_PATH}")

    # ── Save artifacts ──
    joblib.dump(vectorizer, MODEL_DIR / "tfidf_vectorizer.pkl")
    joblib.dump(model, MODEL_DIR / "lr_model.pkl")
    joblib.dump({"threshold": DECISION_THRESHOLD}, MODEL_DIR / "threshold.pkl")
    print(f"Model artifacts saved to {MODEL_DIR}/")


if __name__ == "__main__":
    main()
