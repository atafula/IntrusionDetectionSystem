import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib
import os

DATA_PATH = '../data/datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
MODEL_PATH = '../models/model.pkl'
FEATURES_PATH = '../models/feature_columns.pkl'

# Load dataset
df = pd.read_csv(DATA_PATH, skipinitialspace=True)
print(df.columns)  # Check columns to ensure 'Label' is correctly detected

# Basic cleaning
df = df.dropna()
df = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], errors='ignore')

# Label encoding: 0 = BENIGN, 1 = attack
df['Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in x else 1)

# Separate features and labels
X = df.drop(columns=['Label'])
y = df['Label']

# Encode categorical variables if any exist
for col in X.select_dtypes(include='object').columns:
    X[col] = LabelEncoder().fit_transform(X[col])

# Replace infinite values with NaN and drop rows containing NaN
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X = X.dropna()
y = y.loc[X.index]  # Keep label alignment with features

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Save feature columns list (to keep order)
feature_columns = X.columns.tolist()
joblib.dump(feature_columns, FEATURES_PATH)

# Train Random Forest classifier
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# Create 'models' directory if it doesn't exist
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

# Save the trained model
joblib.dump(model, MODEL_PATH)
print("Model trained and saved at:", MODEL_PATH)
print("Feature columns saved at:", FEATURES_PATH)
