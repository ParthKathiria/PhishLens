import pandas as pd
from ml.config import DATA_DIR, CSV_NAME


def load_phishing_data() -> pd.DataFrame:
    path = DATA_DIR / CSV_NAME
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found at {path}")

    df = pd.read_csv(path)

    df.rename(columns={"text_combined": "text"}, inplace=True)

    before = len(df)
    df.dropna(subset=["text", "label"], inplace=True)
    print(f"Dropped {before - len(df)} rows with null text or label")

    before = len(df)
    df.drop_duplicates(subset=["text"], keep="first", inplace=True)
    print(f"Dropped {before - len(df)} duplicate text rows")

    df["label"] = df["label"].astype(int)

    print(f"\nDataset: {len(df)} emails ({df['label'].sum()} phishing, "
          f"{(df['label'] == 0).sum()} legitimate)")
    print(f"Phishing ratio: {df['label'].mean():.1%}\n")

    return df[["text", "label"]]
