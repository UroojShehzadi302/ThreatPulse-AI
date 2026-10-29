import os
import threading
import joblib
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'random_forest_model.pkl')
SCALER_PATH = os.path.join(BASE_DIR, 'models', 'scaler.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'models', 'feature_names.pkl')
MAPPINGS_PATH = os.path.join(BASE_DIR, 'models', 'category_mappings.pkl')
TRAIN_DATA_PATH = os.path.join(BASE_DIR, 'datasets', 'train_data.csv')

CATEGORY_COLS = ['proto', 'state', 'service']

# Everyday home traffic the model never saw in UNSW-NB15 (DNS to a router, QUIC) scores 0.5-0.6,
# while UNSW-style attacks score 0.84+. On the test set 0.8 keeps 99.33% accuracy (96% recall).
ATTACK_THRESHOLD = 0.8


def build_category_mappings(df):
    """Rebuilds the exact encodings train.py produced with astype('category').cat.codes,
    plus the (state, sttl, dttl) -> ct_state_ttl lookup used by UNSW-NB15."""
    mappings = {}
    for col in CATEGORY_COLS:
        categories = df[col].fillna("Unknown").astype('category').cat.categories
        mappings[col] = {value: code for code, value in enumerate(categories)}

    states = df['state'].fillna("Unknown")
    ttl_groups = df.assign(state=states).groupby(['state', 'sttl', 'dttl'])['ct_state_ttl']
    mappings['ct_state_ttl'] = ttl_groups.agg(lambda s: int(s.mode().iloc[0])).to_dict()
    return mappings


def load_category_mappings():
    if os.path.exists(MAPPINGS_PATH):
        return joblib.load(MAPPINGS_PATH)
    if not os.path.exists(TRAIN_DATA_PATH):
        raise FileNotFoundError("category_mappings.pkl not found and training data is unavailable to rebuild it.")

    print("Building category mappings from training data (one-time)...")
    cols = CATEGORY_COLS + ['sttl', 'dttl', 'ct_state_ttl']
    df = pd.read_csv(TRAIN_DATA_PATH, usecols=cols, low_memory=False)
    mappings = build_category_mappings(df)
    joblib.dump(mappings, MAPPINGS_PATH)
    return mappings


class LivePredictor:
    """Loads the trained Random Forest once and classifies live flow feature dicts."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.features = None
        self.mappings = None
        self.error = None
        self._lock = threading.Lock()

    @property
    def is_ready(self):
        return self.model is not None

    def load(self):
        with self._lock:
            if self.model is not None:
                return True
            try:
                if not os.path.exists(MODEL_PATH):
                    raise FileNotFoundError("Model file not found.")
                self.mappings = load_category_mappings()
                self.scaler = joblib.load(SCALER_PATH)
                self.features = joblib.load(FEATURES_PATH)
                model = joblib.load(MODEL_PATH)
                # Live batches are small; thread fan-out costs more than it saves
                model.n_jobs = 1
                self.model = model
                self.error = None
            except Exception as e:
                self.error = str(e)
                print(f"[LivePredictor] Failed to load model: {e}")
            return self.model is not None

    def ct_state_ttl(self, state, sttl, dttl):
        return self.mappings['ct_state_ttl'].get((state, sttl, dttl), 0)

    def predict(self, flow_features):
        """Returns a list of (label, attack_probability) for each feature dict."""
        if not flow_features or not self.load():
            return []

        X = pd.DataFrame(flow_features)
        for col in CATEGORY_COLS:
            X[col] = X[col].map(self.mappings[col]).fillna(-1).astype(int)
        for feature in self.features:
            if feature not in X.columns:
                X[feature] = 0

        X = X[self.features].astype(float)
        X.replace([np.inf, -np.inf], 0, inplace=True)
        X = X.fillna(0)

        X_scaled = self.scaler.transform(X)
        attack_index = list(self.model.classes_).index(1)
        probabilities = self.model.predict_proba(X_scaled)[:, attack_index]

        return [("Attack" if p >= ATTACK_THRESHOLD else "Normal", float(p)) for p in probabilities]


predictor_instance = LivePredictor()
