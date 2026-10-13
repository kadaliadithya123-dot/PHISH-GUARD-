"""
PHISH GUARD - Data Preprocessing Module
Cleans raw URL dataset, handles missing values, removes duplicates,
extracts all 30 engineered features, and splits into train/test sets.
"""

import os
import sys
from typing import Tuple
import numpy as np
import pandas as pd

# Add backend to path for feature_extractor import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from feature_extractor import extract_features, get_feature_names


def load_and_clean_data(csv_path: str) -> pd.DataFrame:
    """
    Loads raw CSV dataset, performs data sanitation:
    - Drops null/empty rows
    - Removes duplicate URLs
    - Validates label types
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset file not found at: {csv_path}")

    df = pd.read_csv(csv_path)
    initial_count = len(df)
    
    # 1. Drop missing values
    df.dropna(subset=["url", "label"], inplace=True)
    
    # 2. Ensure labels are integers
    df["label"] = df["label"].astype(int)
    
    # 3. Strip whitespace
    df["url"] = df["url"].astype(str).str.strip()
    
    # 4. Remove duplicate URLs
    df.drop_duplicates(subset=["url"], inplace=True)
    
    final_count = len(df)
    print(f"[*] Dataset cleaned: {initial_count} initial records -> {final_count} unique records.")
    return df


def extract_features_from_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Processes all URLs in DataFrame through the feature extractor.
    Returns:
        (X: feature DataFrame, y: target Series)
    """
    feature_names = get_feature_names()
    rows = []
    
    print(f"[*] Extracting {len(feature_names)} features for {len(df)} URLs...")
    for idx, url in enumerate(df["url"]):
        if (idx + 1) % 500 == 0 or idx == len(df) - 1:
            print(f"    - Processed {idx + 1}/{len(df)} URLs...")
        feats, _, _ = extract_features(url)
        rows.append([feats[name] for name in feature_names])

    X = pd.DataFrame(rows, columns=feature_names)
    y = df["label"].reset_index(drop=True)
    
    return X, y


def prepare_preprocessed_dataset(
    csv_path: str,
    output_features_csv: str = None
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    High-level pipeline: loads, cleans, extracts features, and optionally caches features to CSV.
    """
    df = load_and_clean_data(csv_path)
    X, y = extract_features_from_dataframe(df)
    
    if output_features_csv:
        combined = X.copy()
        combined["label"] = y
        combined.to_csv(output_features_csv, index=False)
        print(f"[+] Preprocessed feature matrix saved to: {output_features_csv}")
        
    return X, y


if __name__ == "__main__":
    from generate_dataset import OUTPUT_CSV, create_dataset
    if not os.path.exists(OUTPUT_CSV):
        create_dataset()
    X, y = prepare_preprocessed_dataset(OUTPUT_CSV)
    print(f"[+] Feature matrix shape: {X.shape}, Target shape: {y.shape}")
