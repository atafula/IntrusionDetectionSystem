# Intrusion Detection System (IDS)

A Java-based Intrusion Detection System (IDS) that analyzes network traffic in real time and leverages a machine learning model to detect attacks such as DoS, port scanning, and other threats.

## Technologies
- **Java**: Packet capture and processing
- **Python**: Machine learning model training and evaluation
- **scikit-learn**: Python machine learning library
- **libpcap / jNetPcap / tshark**: Network traffic capture and analysis tools

## Project Structure
- `src/` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Java source code
- `scripts/` &nbsp;&nbsp;&nbsp;&nbsp;→ Python scripts for ML training and preprocessing
- `data/` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Datasets and packet capture files
- `models/` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Trained ML models
- `docs/` &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Documentation and architecture diagrams

## How to Run

1. **Train the machine learning model**  
   Execute the training script:
   ```sh
   python scripts/train_model.py
   ```
2. **Start the real-time IDS**  
   Compile and run the main Java class:
   ```sh
   javac -d build src/main/ids/*.java
   java -cp build ids.Main
   ```
3. The system will analyze network packets and trigger alerts upon detecting suspicious activity.

## Project Status
🔸 In development — initial version.

## Author
- Adrián Tafula - [@atafula](https://github.com/atafula)
