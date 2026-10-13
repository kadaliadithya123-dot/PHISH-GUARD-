"""
PHISH GUARD - Machine Learning Training & Evaluation Pipeline
Trains, evaluates, and benchmarks 7 distinct classification algorithms:
1. Logistic Regression
2. Decision Tree
3. Random Forest
4. Support Vector Machine (SVC)
5. K-Nearest Neighbors (KNN)
6. Naive Bayes (Gaussian NB)
7. Gradient Boosting

Automatically computes Accuracy, Precision, Recall, F1 Score, ROC-AUC,
Confusion Matrix, and Training Time. Selects the champion model and exports
all production artifacts (model.pkl, scaler.pkl, metadata.json, confusion_matrix.png).
"""

import json
import os
import sys
import time
from typing import Any, Dict

import joblib
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless environments
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

# Setup directory paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATASET_CSV = os.path.join(DATASET_DIR, "urls_dataset.csv")

# Add backend and dataset to path
sys.path.append(os.path.join(BASE_DIR, "backend"))
sys.path.append(DATASET_DIR)

from data_preprocessing import prepare_preprocessed_dataset
from generate_dataset import create_dataset
from feature_extractor import get_feature_names
import database_manager


def train_and_evaluate_pipeline():
    print("=" * 75)
    print("   PHISH GUARD - MULTI-MODEL TRAINING & BENCHMARKING PIPELINE")
    print("=" * 75)

    # 1. Dataset verification or generation
    if not os.path.exists(DATASET_CSV):
        print(f"[*] Dataset not found at {DATASET_CSV}. Generating new dataset...")
        create_dataset(DATASET_CSV, total_samples=4000)

    # 2. Preprocess & extract features
    features_cache_csv = os.path.join(DATASET_DIR, "features_extracted.csv")
    if os.path.exists(features_cache_csv):
        print(f"[*] Loading pre-extracted features from {features_cache_csv}...")
        df_feats = pd.read_csv(features_cache_csv)
        feature_names = get_feature_names()
        X = df_feats[feature_names]
        y = df_feats["label"]
    else:
        print("[*] Extracting features from dataset...")
        X, y = prepare_preprocessed_dataset(DATASET_CSV, output_features_csv=features_cache_csv)

    print(f"[+] Total samples: {len(X)} | Features per sample: {X.shape[1]}")
    print(f"[+] Class distribution: Safe (0) = {sum(y == 0)}, Phishing (1) = {sum(y == 1)}")

    # 3. Train / Test Split
    print("[*] Splitting dataset into 80% Training and 20% Testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Train set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # 4. Feature Scaling
    print("[*] Fitting StandardScaler on training feature vectors...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler immediately
    scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"[+] Scaler saved to: {scaler_path}")

    # 5. Define candidate algorithms
    candidate_models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=16, random_state=42, n_jobs=-1
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42
        ),
        "Support Vector Machine (SVC)": SVC(
            probability=True, kernel="rbf", C=1.0, random_state=42
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, C=1.0, random_state=42
        ),
        "K-Nearest Neighbors": KNeighborsClassifier(
            n_neighbors=5, n_jobs=-1
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, random_state=42
        ),
        "Naive Bayes (Gaussian)": GaussianNB()
    }

    # 6. Benchmarking & Training Loop
    results = {}
    fitted_models = {}

    print("\n" + "-" * 75)
    print(f"{'Algorithm':<28} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8} | {'Time (s)':<8}")
    print("-" * 75)

    for name, model in candidate_models.items():
        start_time = time.perf_counter()
        model.fit(X_train_scaled, y_train)
        training_time = time.perf_counter() - start_time

        # Predictions
        y_pred = model.predict(X_test_scaled)
        
        # Probabilities for ROC-AUC
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test_scaled)[:, 1]
        elif hasattr(model, "decision_function"):
            y_proba = model.decision_function(X_test_scaled)
        else:
            y_proba = y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc = roc_auc_score(y_test, y_proba)
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc), 4),
            "training_time": round(float(training_time), 4),
            "confusion_matrix": cm.tolist()
        }
        fitted_models[name] = model

        print(
            f"{name:<28} | {acc:<8.4f} | {prec:<9.4f} | {rec:<8.4f} | {f1:<8.4f} | {roc:<8.4f} | {training_time:<8.3f}"
        )

    print("-" * 75)

    # 7. Select Champion Model based on balanced F1-score & ROC-AUC
    best_model_name = max(results.keys(), key=lambda k: (results[k]["f1_score"], results[k]["roc_auc"]))
    best_model = fitted_models[best_model_name]
    best_metrics = results[best_model_name]

    print(f"\n[+] CHAMPION MODEL SELECTED: {best_model_name}")
    print(f"    - Accuracy:  {best_metrics['accuracy'] * 100:.2f}%")
    print(f"    - F1 Score:  {best_metrics['f1_score']:.4f}")
    print(f"    - Precision: {best_metrics['precision']:.4f}")
    print(f"    - Recall:    {best_metrics['recall']:.4f}")
    print(f"    - ROC-AUC:   {best_metrics['roc_auc']:.4f}")
    print(f"    - Training:  {best_metrics['training_time']:.3f} seconds")

    # 8. Save Champion Model artifact
    model_save_path = os.path.join(MODELS_DIR, "model.pkl")
    joblib.dump(best_model, model_save_path)
    print(f"[+] Champion model artifact saved to: {model_save_path}")

    # 9. Plot and Save Confusion Matrix Visualization
    cm = np.array(best_metrics["confusion_matrix"])
    plt.figure(figsize=(6, 5))
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title(f"Confusion Matrix - {best_model_name}", fontsize=12, pad=15)
    plt.colorbar()
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ["Safe (0)", "Phishing (1)"], fontsize=10)
    plt.yticks(tick_marks, ["Safe (0)", "Phishing (1)"], fontsize=10)

    # Annotate cells with counts
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(
                j, i, format(cm[i, j], "d"),
                horizontalalignment="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=14,
                fontweight="bold"
            )

    plt.ylabel("True Label", fontsize=11)
    plt.xlabel("Predicted Label", fontsize=11)
    plt.tight_layout()
    cm_path = os.path.join(MODELS_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[+] Confusion matrix visual saved to: {cm_path}")

    # 10. Extract Feature Importances (if supported by best model)
    feature_importances = {}
    if hasattr(best_model, "feature_importances_"):
        raw_importances = best_model.feature_importances_
        feature_names = get_feature_names()
        for feat_name, imp in zip(feature_names, raw_importances):
            feature_importances[feat_name] = round(float(imp), 4)
        # Sort descending
        feature_importances = dict(sorted(feature_importances.items(), key=lambda item: item[1], reverse=True))

    # 11. Save Comprehensive Metadata JSON
    metadata = {
        "active_model_name": best_model_name,
        "feature_count": len(get_feature_names()),
        "feature_names": get_feature_names(),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "champion_metrics": best_metrics,
        "all_model_benchmarks": results,
        "feature_importances": feature_importances,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    metadata_path = os.path.join(MODELS_DIR, "metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Metadata & benchmarks saved to: {metadata_path}")

    # Synchronize benchmarks into SQLite database
    try:
        database_manager.save_model_benchmarks(results, best_model_name)
        print("[+] Model benchmarks successfully synced into SQLite database.")
    except Exception as e:
        print(f"[!] Warning: Could not sync benchmarks to database: {e}")

    print("\n[+] ML Pipeline execution completed successfully!")
    return metadata


if __name__ == "__main__":
    train_and_evaluate_pipeline()
