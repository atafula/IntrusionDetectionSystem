import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

DATA_PATH = '../data/datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
MODEL_PATH = '../models/model.pkl'

# Load dataset
df = pd.read_csv(DATA_PATH, skipinitialspace=True)
df.dropna(inplace=True)  # Drop rows with missing values
df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], errors='ignore', inplace=True)  # Drop unused columns

# Convert label to binary: 0 for BENIGN, 1 for ATTACK
df['Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in x else 1)

# Separate features and labels
X = df.drop(columns=['Label'])
y = df['Label']

# Encode categorical features as numeric
for col in X.select_dtypes(include='object').columns:
    X[col] = LabelEncoder().fit_transform(X[col])

# Replace infinite values with NaN and drop those rows
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.dropna(inplace=True)
y = y.loc[X.index]  # Align labels with cleaned feature rows

# Split dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Load trained model
model = joblib.load(MODEL_PATH)

# Make predictions on the test set
y_pred = model.predict(X_test)

# Print confusion matrix
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Print detailed classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
