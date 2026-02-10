#!/usr/bin/env python3
import scapy.all as scapy
import threading
import requests
import joblib
import time
import sqlite3
import numpy as np
from statistics import mean, stdev
from sklearn.preprocessing import LabelEncoder
import subprocess
import warnings
warnings.filterwarnings("ignore")

class RFIDS:
    def __init__(self):
        # Model configuration
        self.model = joblib.load("rf_model_nsl_kdd.pkl")
        self.label_encoder = LabelEncoder()
        self.label_encoder.classes_ = np.load('le2_classes.npy', allow_pickle=True)
        
        # Thresholds
        self.CONFIDENCE_THRESHOLD = 0.4
        self.ANOMALY_THRESHOLD = 2.0
        self.ANOMALY_ALERT_THRESHOLD = 2.0  # Lower threshold for alerts
        
        # Whitelist
        self.whitelist_ips = {"192.168.35.59"}
        
        # Traffic monitoring
        self.traffic_window = []
        self.WINDOW_SIZE = 100
        self.baseline_established = False
        self.baseline_stats = {'mean': 0, 'stdev': 0}
        
        # Blocking
        self.blocked_ips = set()
        self.block_timeout = 3600
        
        # Notification services
        self.TELEGRAM_BOT_TOKEN = "7498541863:AAEv2zcum-CLQs0imZBcfgK0T09F6d8CNGA"
        self.TELEGRAM_CHAT_ID = "5189291324"
        self.BREVO_API_KEY = "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"
        self.BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
        self.BREVO_SENDER_NAME = "IDS Alert System"
        self.BREVO_SENDER_EMAIL = "jyotiprakashm182@gmail.com"
        self.BREVO_RECEIVER_EMAIL = "kalpana.ay86@gmail.com"
        
        # Initialize
        self.init_db()
        self.test_alert_systems()

    def init_db(self):
        """Initialize database with existing structure"""
        conn = sqlite3.connect("ids_logs.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS logs 
                         (timestamp TEXT, event_type TEXT, source_ip TEXT, details TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS blocked_ips 
                         (ip TEXT PRIMARY KEY, timestamp TEXT, reason TEXT)''')
        conn.commit()
        conn.close()

    def test_alert_systems(self):
        """Test all alert channels at startup"""
        print("\nTesting alert systems...")
        # Test Telegram
        if self.send_telegram_alert("🚨 IDS Alert System Test - Telegram"):
            print("Telegram test successful")
        else:
            print("Telegram test failed")
        
        # Test Email
        if self.send_email_alert("IDS Alert System Test", "This is a test email from the IDS system"):
            print("Email test successful")
        else:
            print("Email test failed")
        print("Alert testing complete\n")

    def send_telegram_alert(self, message):
        """Send alert via Telegram with error handling"""
        try:
            telegram_url = f"https://api.telegram.org/bot{self.TELEGRAM_BOT_TOKEN}/sendMessage"
            response = requests.post(
                telegram_url,
                data={
                    "chat_id": self.TELEGRAM_CHAT_ID,
                    "text": message,
                    "parse_mode": "Markdown"
                },
                timeout=10
            )
            if response.status_code != 200:
                print(f"Telegram API Error: {response.text}")
                return False
            return True
        except Exception as e:
            print(f"Telegram Error: {str(e)}")
            return False

    def send_email_alert(self, subject, message):
        """Send alert via Brevo email API"""
        try:
            headers = {
                "accept": "application/json",
                "api-key": self.BREVO_API_KEY,
                "content-type": "application/json"
            }
            data = {
                "sender": {
                    "name": self.BREVO_SENDER_NAME,
                    "email": self.BREVO_SENDER_EMAIL
                },
                "to": [{"email": self.BREVO_RECEIVER_EMAIL}],
                "subject": subject,
                "htmlContent": f"<html><body><p>{message}</p></body></html>"
            }
            response = requests.post(self.BREVO_API_URL, json=data, headers=headers, timeout=10)
            if response.status_code != 201:
                print(f"Email API Error: {response.text}")
                return False
            return True
        except Exception as e:
            print(f"Email Error: {str(e)}")
            return False

    def trigger_alerts(self, alert_type, src_ip, confidence, details=""):
        """Unified alert triggering for both channels"""
        if alert_type == "Traffic_Anomaly":
            message = f"🚨 Traffic Anomaly Detected\nSource: {src_ip}\nScore: {confidence:.2f}\nDetails: {details}"
            email_subject = f"Traffic Anomaly from {src_ip}"
        else:
            message = f"🚨 Intrusion Detected\nType: {alert_type}\nSource: {src_ip}\nConfidence: {confidence:.2%}\nDetails: {details}"
            email_subject = f"Intrusion Alert: {alert_type} from {src_ip}"
        
        # Log to database
        self.log_event(alert_type, src_ip, details)
        
        # Send alerts with fallback
        telegram_sent = self.send_telegram_alert(message)
        if not telegram_sent:
            print("Falling back to email notification")
            self.send_email_alert(email_subject, message)

    def extract_features(self, packet):
        """Extract features from packet"""
        features = np.zeros(self.model.n_features_in_)
        try:
            if packet.haslayer(scapy.IP):
                ip = packet[scapy.IP]
                features[0] = 0  # duration
                features[1] = ip.proto  # protocol_type
                features[4] = len(packet)  # src_bytes
                features[5] = 0  # dst_bytes
                
                if packet.haslayer(scapy.TCP):
                    tcp = packet[scapy.TCP]
                    features[3] = int(tcp.flags)  # flag
                    features[5] = len(tcp.payload) if packet.haslayer(scapy.Raw) else 0
                
                return features, ip.src
        except Exception as e:
            print(f"Feature extraction error: {e}")
        return None, None

    def update_traffic_baseline(self, packet_size):
        """Update traffic baseline statistics"""
        self.traffic_window.append(packet_size)
        if len(self.traffic_window) > self.WINDOW_SIZE:
            self.traffic_window.pop(0)
            
        if len(self.traffic_window) >= 50:
            self.baseline_stats['mean'] = mean(self.traffic_window)
            self.baseline_stats['stdev'] = stdev(self.traffic_window) if len(self.traffic_window) > 1 else 0
            self.baseline_established = True

    def detect_anomalies(self, packet_size):
        """Detect traffic anomalies"""
        if not self.baseline_established:
            return False, 0
            
        z_score = (packet_size - self.baseline_stats['mean']) / self.baseline_stats['stdev'] if self.baseline_stats['stdev'] > 0 else 0
        return z_score > self.ANOMALY_THRESHOLD, z_score

    def detect_intrusion(self, features):
        """Detect intrusions using ML model"""
        try:
            prediction = self.model.predict(features.reshape(1, -1))
            probabilities = self.model.predict_proba(features.reshape(1, -1))[0]
            confidence = probabilities[prediction[0]]
            attack_type = self.label_encoder.inverse_transform(prediction)[0]
            return attack_type, confidence
        except Exception as e:
            print(f"Prediction error: {str(e)}")
            return "normal", 0.0

    def block_ip(self, ip, reason=""):
        """Block IP using iptables"""
        if ip in self.whitelist_ips or ip in self.blocked_ips:
            return
            
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                stderr=subprocess.PIPE
            )
            self.blocked_ips.add(ip)
            print(f"Blocked IP {ip} - Reason: {reason}")
            self.log_event("IP_Blocked", ip, reason)
            
            threading.Timer(
                self.block_timeout,
                lambda: self.unblock_ip(ip)
            ).start()
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to block IP {ip}: {str(e.stderr.decode())}")

    def unblock_ip(self, ip):
        """Unblock IP after timeout"""
        try:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
            self.blocked_ips.remove(ip)
            print(f"Unblocked IP {ip}")
        except:
            pass

    def log_event(self, event_type, source_ip="", details=""):
        """Log events to existing database structure"""
        conn = sqlite3.connect("ids_logs.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs (timestamp, event_type, source_ip, details) VALUES (?, ?, ?, ?)", 
                      (time.ctime(), event_type, source_ip, details))
        conn.commit()
        conn.close()

    def process_packet(self, packet):
        """Process each network packet with enhanced alerting"""
        try:
            features, src_ip = self.extract_features(packet)
            if features is None or not src_ip:
                return
                
            if src_ip in self.whitelist_ips:
                return
                
            packet_size = len(packet)
            self.update_traffic_baseline(packet_size)
            
            # Detect anomalies
            anomaly, score = self.detect_anomalies(packet_size)
            if anomaly and score > self.ANOMALY_ALERT_THRESHOLD:
                print(f"Traffic anomaly from {src_ip} (score: {score:.2f})")
                self.trigger_alerts(
                    "Traffic_Anomaly",
                    src_ip,
                    score,
                    f"Packet size: {packet_size} bytes, Score: {score:.2f}"
                )
            
            # Detect intrusions
            attack_type, confidence = self.detect_intrusion(features)
            
            if attack_type != "normal":
                if confidence > self.CONFIDENCE_THRESHOLD:
                    print(f"🚨 Attack detected: {attack_type} from {src_ip} (confidence: {confidence:.2%})")
                    self.trigger_alerts(
                        attack_type,
                        src_ip,
                        confidence,
                        f"Anomaly score: {score:.2f}" if anomaly else "No significant anomaly"
                    )
                    self.block_ip(src_ip, f"{attack_type} attack")
                else:
                    print(f"Suspicious activity ({attack_type}) from {src_ip} (confidence: {confidence:.2%})")
                
        except Exception as e:
            print(f"Packet processing error: {str(e)}")

    def start(self, interface="eth0"):
        """Start the IDS on specified interface"""
        print(f"Starting IDS on interface {interface}...")
        
        available_interfaces = scapy.get_if_list()
        print(f"Available interfaces: {available_interfaces}")
        
        if interface not in available_interfaces:
            interface = available_interfaces[0]
            print(f"Warning: Specified interface not found. Using {interface} instead")
        
        print("Performing test capture (5 packets)...")
        try:
            test_packets = scapy.sniff(iface=interface, count=5, timeout=10)
            if len(test_packets) == 0:
                print("No packets received! Check your interface and network connection.")
                print("Possible solutions:")
                print("1. Try a different interface")
                print("2. Check network cables/connections")
                print("3. Run with 'sudo' if not already")
                return
            else:
                print(f"Successfully captured {len(test_packets)} test packets")
        except Exception as e:
            print(f"Test capture failed: {str(e)}")
            return
        
        print("\nStarting main packet processing...")
        print("Press Ctrl+C to stop\n")
        
        packet_count = 0
        def verbose_callback(packet):
            nonlocal packet_count
            packet_count += 1
            if packet_count % 50 == 0:
                print(f"Processed {packet_count} packets...")
            self.process_packet(packet)
        
        try:
            scapy.sniff(
                iface=interface,
                prn=verbose_callback,
                store=False,
                filter="ip or arp"
            )
        except KeyboardInterrupt:
            print("\nStopped by user")
        except Exception as e:
            print(f"Sniffing error: {str(e)}")
        finally:
            print(f"\nTotal packets processed: {packet_count}")

if __name__ == "__main__":
    ids = RFIDS()
    ids.start(interface="eth0")
