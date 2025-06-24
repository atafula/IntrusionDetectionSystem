import sys
import joblib
import numpy as np

MODEL_PATH = '../models/final_model.pkl'
FEATURES_PATH = '../models/feature_columns.pkl'

def parse_features():
    
    """
    Reads feature inputs from standard input, expecting each line in 'key=value' format.
    Converts values to float. If conversion fails, exits with an error message.

    Returns:
        dict: A dictionary mapping feature names to their float values.
    """
    features = {}
    for line in sys.stdin:
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, value = line.split('=', 1)
        try:
            features[key] = float(value)
        except ValueError:
            print(f"Invalid value for '{key}', it must be numeric.")
            sys.exit(1)
    return features

def main():
    """
    Main execution function:
    - Parses features from input.
    - Loads the trained model and the expected feature columns.
    - Fills missing features with default value 0.0.
    - Validates the input vector (no NaN or infinite values).
    - Predicts using the loaded model.
    - Prints 'Attack' if prediction is 1, otherwise 'Benign'.
    """
    features = parse_features()

    try:
        model = joblib.load(MODEL_PATH)
        feature_columns = joblib.load(FEATURES_PATH)
    except Exception as e:
        print(f"Error loading model or feature columns: {e}")
        sys.exit(1)

    # Fill missing features with default value 0.0
    for col in feature_columns:
        if col not in features:
            features[col] = 0.0

    input_vector = np.array([[features[col] for col in feature_columns]])

    # Check for NaN or infinite values in input
    if np.any(np.isnan(input_vector)) or np.any(np.isinf(input_vector)):
        print("Input vector contains NaN or infinite values.")
        sys.exit(1)

    result = model.predict(input_vector)[0]
    print("Attack" if result == 1 else "Benign")

if __name__ == "__main__":
    if sys.stdin.isatty():
        print("Please enter features one per line in 'key=value' format and finish with Ctrl+Z (Windows) or Ctrl+D (Linux/Mac).")
    main()
