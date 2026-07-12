import re
import pandas as pd

from ml.config import URL_TOKEN


def strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text)


def replace_urls(text: str) -> str:
    url_pattern = r"https?://\S+|ftp://\S+|www\.\S+"
    return re.sub(url_pattern, URL_TOKEN, text, flags=re.IGNORECASE)


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def clean_text(text: str) -> str:
    text = strip_html(text)
    text = replace_urls(text)
    text = normalize_whitespace(text)
    return text


def preprocess(df: pd.DataFrame, text_col: str = "text") -> pd.DataFrame:
    df = df.copy()
    df[text_col] = df[text_col].apply(clean_text)
    return df
