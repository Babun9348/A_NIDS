# 🚀 A_NIDS – AI-based Network Intrusion Detection System  

An AI-powered Network Intrusion Detection System (A_NIDS) that captures live network packets, analyzes traffic behavior, and detects malicious activities using a trained Machine Learning model.  
The system generates real-time alerts, logs detected attacks, and can automatically block malicious IP addresses.

---

## ✨ Features

- Live packet capturing using Scapy  
- Machine Learning based attack classification (Random Forest)  
- Anomaly detection using statistical analysis  
- SQLite database logging  
- Telegram and Email alert system  
- Automatic IP blocking using iptables  
- Auto-unblock after timeout  

---

## 📂 Project Structure

A_NIDS/
│
├── A_NIDS_FINAL.py  
├── model.ipynb  
├── process.ipynb  
├── requirements.txt  
├── .gitignore  
├── AI_IDS_Project_Presentation.pptx  
├── A_NIDS.docx  
│
├── data/  
│   ├── KDDTrain+.txt  
│   ├── KDDTest+.txt  
│   ├── bin_data.csv  
│   └── multi_data.csv  
│
├── models/  
│   ├── rf_model_nsl_kdd.pkl  
│   └── le2_classes.npy  

---

## 📥 Dataset & Trained Model

Due to GitHub file size limits, the dataset and trained model are not included in this repository.

Download from:

Dataset: ADD_YOUR_LINK_HERE  
Trained Model (.pkl): ADD_YOUR_LINK_HERE  

After downloading:

Place datasets inside: data/  
Place model files inside: models/

---

## ⚙️ Requirements

- Python 3.8 or higher  
- Linux OS (recommended)  
- Root privileges (for packet sniffing & firewall rules)

Install dependencies:

pip install -r requirements.txt  

If requirements.txt is not present:

pip install scapy numpy scikit-learn joblib requests  

---

## ▶️ How It Works

1. Captures network packets in real-time  
2. Extracts important traffic features  
3. Detects anomalies using statistical methods  
4. Classifies traffic using trained ML model  
5. Sends alert if an attack is detected  
6. Logs event into SQLite database  
7. Blocks attacker IP automatically  

---

## ▶️ Run the Project

Find your network interface:

ip a  

Run:

sudo python3 A_NIDS_FINAL.py  

To change interface inside code:

ids.start(interface="wlan0")

---

## 🗃 Logs

All detected events are stored in:

ids_logs.db  

View logs:

sqlite3 ids_logs.db "select * from logs;"

---

## 🔐 Security Note

Do NOT upload real API keys or tokens to GitHub.

Use environment variables for:

- Telegram Bot Token  
- Telegram Chat ID  
- Email API Key  

---

## 🧠 Model Training

process.ipynb → Dataset preprocessing  
model.ipynb → Model training & exporting  

---

## ⚠️ Disclaimer

This project is for educational purposes only.  
Use only in controlled and authorized environments.

---

## 👤 Author

Jyotiprakash Mishra
