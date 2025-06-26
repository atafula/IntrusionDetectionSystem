import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score, accuracy_score
import joblib

DATA_PATH = '../data/datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'

# Load dataset
df = pd.read_csv(DATA_PATH, skipinitialspace=True)
df = df.dropna()  # Drop rows with missing values
df = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], errors='ignore')  # Drop unused columns

# Convert labels to binary: 0 for BENIGN, 1 for ATTACK
df['Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in x else 1)

# Separate features and target label
X = df.drop(columns=['Label'])
y = df['Label']

# Encode categorical features as numeric
for col in X.select_dtypes(include='object').columns:
    X[col] = LabelEncoder().fit_transform(X[col])

# Replace infinite values with NaN and drop those rows
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X = X.dropna()
y = y.loc[X.index]  # Align labels with cleaned features

# Initialize Random Forest classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Set up Stratified K-Fold cross-validation with 5 splits
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

accuracies = []
y_true_all = []
y_pred_all = []

# Cross-validation loop
for fold, (train_index, test_index) in enumerate(skf.split(X, y), 1):
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y.iloc[train_index], y.iloc[test_index]

    model.fit(X_train, y_train)  # Train model on current fold's training data
    y_pred = model.predict(X_test)  # Predict on validation data

    acc = accuracy_score(y_test, y_pred)  # Calculate accuracy for this fold
    accuracies.append(acc)

    y_true_all.extend(y_test)  # Collect true labels
    y_pred_all.extend(y_pred)  # Collect predicted labels

# Print accuracy per fold
print(f"Accuracy por fold: {np.array(accuracies)}")
print(f"Mean Accuracy: {np.mean(accuracies):.4f}\n")

# Print classification report summarizing precision, recall, f1-score
print("Classification Report:")
print(classification_report(y_true_all, y_pred_all, target_names=['BENIGN', 'ATTACK']))

# Print confusion matrix
print("\nConfusion Matrix:")
cm = confusion_matrix(y_true_all, y_pred_all)
print(cm)

# Print overall precision, recall, and F1-score
print(f"\nPrecision: {precision_score(y_true_all, y_pred_all):.4f}")
print(f"Recall:    {recall_score(y_true_all, y_pred_all):.4f}")
print(f"F1-score:  {f1_score(y_true_all, y_pred_all):.4f}")
