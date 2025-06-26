import sys
import joblib
import numpy as np
import json
import os

MODEL_PATH = os.path.join(os.getcwd(), 'models', 'final_model.pkl')
FEATURES_PATH = os.path.join(os.getcwd(), 'models', 'feature_columns.pkl')

def parse_features():
    try:
        input_json = sys.stdin.read()
        features = json.loads(input_json)
        # convert to float
        for k, v in features.items():
            features[k] = float(v)
        return features
    except Exception as e:
        print(f"Error parsing input JSON: {e}")
        sys.exit(1)

def main():
    features = parse_features()

    try:
        model = joblib.load(MODEL_PATH)
        feature_columns = joblib.load(FEATURES_PATH)
    except Exception as e:
        print(f"Error loading model or feature columns: {e}")
        sys.exit(1)

    for col in feature_columns:
        if col not in features:
            features[col] = 0.0

    input_vector = np.array([[features[col] for col in feature_columns]])

    if np.any(np.isnan(input_vector)) or np.any(np.isinf(input_vector)):
        print("Input vector contains NaN or infinite values.")
        sys.exit(1)

    result = model.predict(input_vector)[0]
    print("ATTACK" if result == 1 else "BENIGN")

if __name__ == "__main__":
    main()
