# Intrusion Detection System (IDS)

A Java-based intrusion detection system that analyzes network traffic and uses a machine learning model to detect attacks such as DoS, port scanning, and more.

## 🔧 Technologies
- Java (packet capture and processing)
- Python (machine learning model training)
- scikit-learn
- libpcap / jNetPcap / tshark
- Flask (optional, for a simple web interface)

## 📁 Project Structure
- `src/` → Java source code
- `scripts/` → Python scripts for ML training and preprocessing
- `data/` → Datasets and packet capture files
- `models/` → Trained ML models
- `docs/` → Documentation and architecture diagrams

## 🚀 How to Run
1. Train the ML model using `scripts/train_model.py`
2. Run `Main.java` to launch the real-time IDS
3. Network packets will be analyzed and alerts will be triggered upon suspicious activity

## 📌 Project Status
🔸 In development — initial version.

## ✍️ Author
- Adrián Tafula - [@atafula](https://github.com/atafula)
