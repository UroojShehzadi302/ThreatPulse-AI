import joblib
import pandas as pd
import numpy as np
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'random_forest_model.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'models', 'scaler.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'models', 'feature_names.pkl')

def load_models():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model file not found.")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    features = joblib.load(FEATURES_PATH)
    return model, scaler, features

def predict_data(file_path):
    model, scaler, features = load_models()
    
    # Read the uploaded file
    df = pd.read_csv(file_path, low_memory=False)
    df.columns = df.columns.str.strip()
    original_df = df.copy()
    
    # Check if the dataset has ground truth labels
    actual_labels = None
    if 'Label' in df.columns:
        actual_labels = df['Label'].copy()
    
    # Drop columns that were dropped during training
    drop_cols = ['Label', 'attack_cat', 'srcip', 'dstip', 'Stime', 'Ltime', 'sport', 'dsport']
    X = df.drop(columns=drop_cols, errors='ignore')
    
    # Encode text columns
    for col in ['proto', 'state', 'service']:
        if col in X.columns:
            X[col] = X[col].astype('category').cat.codes
            
    X = X.select_dtypes(include=[np.number])
    X = X.fillna(0)
    X.replace([np.inf, -np.inf], 0, inplace=True)
    
    for feature in features:
        if feature not in X.columns:
            X[feature] = 0
            
    X = X[features]
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)
    
    original_df['Prediction'] = predictions
    original_df['Prediction_Label'] = original_df['Prediction'].map({0: 'Normal', 1: 'Attack'})
    
    total_records = len(original_df)
    normal_count = int((predictions == 0).sum())
    attack_count = int((predictions == 1).sum())
    
    metrics = {}
    
    if actual_labels is not None:
        # Calculate all metrics
        metrics['accuracy'] = f"{accuracy_score(actual_labels, predictions) * 100:.2f}%"
        metrics['precision'] = f"{precision_score(actual_labels, predictions, zero_division=0) * 100:.2f}%"
        metrics['recall'] = f"{recall_score(actual_labels, predictions, zero_division=0) * 100:.2f}%"
        metrics['f1'] = f"{f1_score(actual_labels, predictions, zero_division=0) * 100:.2f}%"
        
        # Generate the Confusion Matrix Heatmap
        cm = confusion_matrix(actual_labels, predictions, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        metrics['confusion_matrix'] = {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        plt.figure(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Purples', 
                    xticklabels=['Normal (0)', 'Attack (1)'], 
                    yticklabels=['Normal (0)', 'Attack (1)'],
                    annot_kws={"size": 16})
        plt.title('Confusion Matrix', fontsize=16, pad=15)
        plt.ylabel('Actual Label', fontsize=12)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.tight_layout()
        
        img_path = os.path.join(BASE_DIR, 'frontend', 'static', 'dynamic_confusion_matrix.png')
        plt.savefig(img_path, dpi=150, bbox_inches='tight')
        plt.close()
    
    return {
        "total": total_records,
        "normal": normal_count,
        "attack": attack_count,
        "metrics": metrics if metrics else None,
        "data": original_df.head(50).to_dict(orient='records')
    }