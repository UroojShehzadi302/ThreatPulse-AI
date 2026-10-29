import socket
import threading
import time
import random

def simulate_port_scan(target_ip="127.0.0.1"):
    print(f"Starting simulated Port Scan on {target_ip}...")
    for port in range(20, 100): 
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect((target_ip, port))
            s.close()
        except:
            pass
        time.sleep(0.05)

def simulate_suspicious_traffic():
    # Mimics the UNSW-NB15 "Generic" DNS attack flows the model was trained on:
    # one-way UDP to port 53, 2 packets of 57 bytes, sent with the testbed attacker TTL of 254
    print("Starting simulated Suspicious Traffic...")
    suspicious_ips = ["198.51.100.1", "203.0.113.1", "192.0.2.1"]
    for _ in range(15):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 254)
            target = (random.choice(suspicious_ips), 53)
            s.sendto(b"FAKE_ATTACK_PAYLOAD_DNS_QUERY", target)
            s.sendto(b"FAKE_ATTACK_PAYLOAD_DNS_QUERY", target)
            s.close()
        except:
            pass
        time.sleep(0.1)

def run_demo_attack():
    t1 = threading.Thread(target=simulate_port_scan)
    t2 = threading.Thread(target=simulate_suspicious_traffic)
    t1.start()
    t2.start()