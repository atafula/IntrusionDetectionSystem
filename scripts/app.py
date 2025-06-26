import os
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

LOG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app.log'))

@app.route('/api/status')
def status():
    return jsonify({"status": "online"})

@app.route('/api/logs')
def logs():
    try:
        with open(LOG_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()[-1000:]
        return jsonify({"logs": lines})
    except Exception as e:
        return jsonify({"logs": [f"Error reading log: {e}"]})

ALERTS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'alerts.log'))

@app.route('/api/alerts')
def alerts():
    alerts = []
    try:
        with open(ALERTS_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        current_alert = None
        details = []
        port = ""
        for line in lines:
            if line.startswith("----- INTRUSION DETECTED at"):
                if current_alert:
                    current_alert["port"] = port if port else ""
                    current_alert["details"] = details
                    alerts.append(current_alert)
                    details = []
                    port = ""
                # Extrae la hora
                time = line.strip().split("at")[-1].replace("-", "").strip()
                current_alert = {"time": time, "port": "", "threat": "INTRUSION", "details": []}
            elif line.startswith("Destination Port:"):
                port = line.strip().split(":")[-1].strip()
                details.append(line.strip())
            elif line.startswith("----------------------------------------------"):
                continue
            elif current_alert is not None:
                details.append(line.strip())
        if current_alert:
            current_alert["port"] = port if port else ""
            current_alert["details"] = details
            alerts.append(current_alert)
    except Exception as e:
        alerts.append({"time": "", "port": "", "threat": "", "details": [f"Error reading alerts: {e}"]})
    return jsonify(alerts)
    

@app.route('/')
def root():
    return send_from_directory('..', 'index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
