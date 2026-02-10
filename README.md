# A_NIDS
# AI-based Network Intrusion Detection System (A_NIDS)

An AI-powered Network Intrusion Detection System that captures live network packets, analyzes traffic behavior, and detects malicious activities using a trained Machine Learning model. The system can generate real-time alerts, log attacks, and automatically block malicious IP addresses.

---

## Features

- Live packet capturing using Scapy  
- Machine Learning based attack classification (Random Forest)  
- Anomaly detection using statistical analysis  
- SQLite database logging  
- Telegram and Email alert system  
- Automatic IP blocking using iptables  
- Auto-unblock after timeout  

---

## Project Structure

A_NIDS/  
│  
├── A_NIDS_FINAL.py  
├── rf_model_nsl_kdd.pkl  
├── le2_classes.npy  
├── ids_logs.db  
├── model.ipynb  
├── process.ipynb  
├── datasets/  
│   ├── KDDTrain+.txt  
│   ├── KDDTest+.txt  
│   ├── bin_data.csv  
│   └── multi_data.csv  
├── AI_IDS_Project_Presentation.pptx  
└── A_NIDS.docx  

---

## Requirements

- Python 3.8 or higher  
- Linux OS (recommended)  
- Root privileges (for packet sniffing & firewall rules)

Install required libraries:

pip install scapy numpy scikit-learn joblib requests

---

## How It Works

1. Captures network packets in real-time  
2. Extracts important traffic features  
3. Detects anomalies using statistical methods  
4. Classifies traffic using trained ML model  
5. Sends alert if an attack is detected  
6. Logs event into database  
7. Blocks attacker IP automatically  

---

## Run the Project

1. Find your network interface:

ip a  

2. Run the program:

sudo python3 A_NIDS_FINAL.py  

To change interface, edit in script:

ids.start(interface="wlan0")

---

## Logs

All detected events are stored in:

ids_logs.db  

View logs:

sqlite3 ids_logs.db "select * from logs;"

---

## Security Note

Do NOT upload real API keys or tokens to GitHub.  
Use environment variables for:

- Telegram Bot Token  
- Telegram Chat ID  
- Email API Key  

---

## Model Training

- process.ipynb → dataset preprocessing  
- model.ipynb → training and exporting model  

---

## Disclaimer

This project is for educational purposes only.  
Use in controlled environments.

---

## Author

Jyotiprakash Mishra  
 

---

