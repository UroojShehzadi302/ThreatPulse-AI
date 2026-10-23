import pandas as pd
import joblib
import os
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

def load_and_clean_data(train_path, test_path):
    print("Loading prepared datasets...")
    train_df = pd.read_csv(train_path, low_memory=False)
    test_df = pd.read_csv(test_path, low_memory=False)
    
    train_df.columns = train_df.columns.str.strip()
    test_df.columns = test_df.columns.str.strip()
    
    string_cols = ['proto', 'state', 'service']
    for col in string_cols:
        if col in train_df.columns:
            train_df[col] = train_df[col].fillna("Unknown")
        if col in test_df.columns:
            test_df[col] = test_df[col].fillna("Unknown")
            
    numeric_cols_train = train_df.select_dtypes(include=[np.number]).columns
    numeric_cols_test = test_df.select_dtypes(include=[np.number]).columns
    
    train_df[numeric_cols_train] = train_df[numeric_cols_train].fillna(0)
    test_df[numeric_cols_test] = test_df[numeric_cols_test].fillna(0)
    
    train_df.replace([np.inf, -np.inf], 0, inplace=True)
    test_df.replace([np.inf, -np.inf], 0, inplace=True)
    
    print(f"Total Training records: {len(train_df)}")
    print(f"Total Testing records: {len(test_df)}")
    
    return train_df, test_df

def preprocess_data(train_df, test_df):
    drop_cols = ['Label', 'attack_cat', 'srcip', 'dstip', 'Stime', 'Ltime', 'sport', 'dsport']
    
    X_train = train_df.drop(columns=drop_cols, errors='ignore')
    y_train = train_df['Label']
    
    X_test = test_df.drop(columns=drop_cols, errors='ignore')
    y_test = test_df['Label']
    
    for col in ['proto', 'state', 'service']:
        if col in X_train.columns:
            X_train[col] = X_train[col].astype('category').cat.codes
        if col in X_test.columns:
            X_test[col] = X_test[col].astype('category').cat.codes
            
    X_train = X_train.select_dtypes(include=[np.number])
    X_test = X_test.select_dtypes(include=[np.number])
    
    common_cols = X_train.columns.intersection(X_test.columns)
    X_train = X_train[common_cols]
    X_test = X_test[common_cols]
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    return X_train_scaled, X_test_scaled, y_train, y_test, scaler, common_cols.tolist()

def plot_confusion_matrix(y_test, y_pred, save_path):
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Purples', 
                xticklabels=['Normal (0)', 'Attack (1)'], 
                yticklabels=['Normal (0)', 'Attack (1)'],
                annot_kws={"size": 16})
    
    plt.title('ThreatPulse AI - Confusion Matrix', fontsize=16, pad=15)
    plt.ylabel('Actual Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    
    os.makedirs('../frontend/static', exist_ok=True)
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Confusion Matrix saved at: {save_path}")

def train_model(train_path, test_path):
    train_df, test_df = load_and_clean_data(train_path, test_path)
    X_train, X_test, y_train, y_test, scaler, feature_names = preprocess_data(train_df, test_df)
    
    print("\nTraining Random Forest Model...")
    model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1, class_weight='balanced')
    model.fit(X_train, y_train)
    
    print("Model training complete. Evaluating...")
    y_pred = model.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    print("\n" + "="*40)
    print("📊 EVALUATION METRICS")
    print("="*40)
    print(f"Accuracy : {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall   : {rec * 100:.2f}%")
    print(f"F1-Score : {f1 * 100:.2f}%")
    print("="*40)
    
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, labels=[0, 1], target_names=["Normal", "Attack"], zero_division=0))
    
    # Save Confusion Matrix Image
    cm_path = '../frontend/static/confusion_matrix.png'
    plot_confusion_matrix(y_test, y_pred, cm_path)
    
    # Save Model Artifacts
    os.makedirs('../models', exist_ok=True)
    joblib.dump(model, '../models/random_forest_model.pkl')
    joblib.dump(scaler, '../models/scaler.pkl')
    joblib.dump(feature_names, '../models/feature_names.pkl')
    
    # Save Metrics to JSON for the UI
    metrics_data = {
        "accuracy": f"{acc * 100:.2f}%",
        "precision": f"{prec * 100:.2f}%",
        "recall": f"{rec * 100:.2f}%",
        "f1_score": f"{f1 * 100:.2f}%",
        "total_records": len(y_test),
        "normal_records": int((y_test == 0).sum()),
        "attack_records": int((y_test == 1).sum())
    }
    
    metrics_path = '../frontend/static/training_metrics.json'
    with open(metrics_path, 'w') as f:
        json.dump(metrics_data, f)
        
    print("\n✅ Model, Confusion Matrix, and Metrics saved successfully!")

if __name__ == "__main__":
    TRAIN_PATH = "../datasets/train_data.csv"
    TEST_PATH = "../datasets/test_data.csv"
    train_model(TRAIN_PATH, TEST_PATH)