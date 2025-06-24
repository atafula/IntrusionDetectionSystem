import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

DATA_PATH = '../data/datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
MODEL_PATH = '../models/final_model.pkl'
FEATURES_PATH = '../models/feature_columns.pkl'

# Load dataset
df = pd.read_csv(DATA_PATH, skipinitialspace=True)
df = df.dropna()  # Drop rows with missing values
df = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], errors='ignore')  # Drop unnecessary columns

# Label encoding: 0 = BENIGN, 1 = attack
df['Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in x else 1)

# Separate features and labels
X = df.drop(columns=['Label'])
y = df['Label']

# Encode categorical variables if any
for col in X.select_dtypes(include='object').columns:
    X[col] = LabelEncoder().fit_transform(X[col])

# Replace infinite values and drop invalid rows
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X = X.dropna()
y = y.loc[X.index]  # Keep labels aligned with features

# Save the list of feature columns (order matters)
feature_columns = X.columns.tolist()

# Train model on entire dataset
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Create 'models' directory if it does not exist
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

# Save trained model and feature columns
joblib.dump(model, MODEL_PATH)
joblib.dump(feature_columns, FEATURES_PATH)

print("Final model trained and saved at:", MODEL_PATH)
print("Feature columns saved at:", FEATURES_PATH)