import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import socket
import psutil

class LiveMonitor:
    def __init__(self):
        self.is_running = False
        self.packet_count = 0
        self.recent_packets = []
        self.thread = None

    def start(self):
        if not self.is_running:
            self.is_running = True
            self.packet_count = 0
            self.recent_packets = []
            self.thread = threading.Thread(target=self._capture_packets)
            self.thread.daemon = True
            self.thread.start()

    def stop(self):
        self.is_running = False

    def _capture_packets(self):
        sniff(prn=self._process_packet, stop_filter=lambda x: not self.is_running, store=False)

    def _get_process_name(self, local_port):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == local_port and conn.pid:
                    process = psutil.Process(conn.pid)
                    return process.name()
        except:
            pass
        return "Unknown"

    def _process_packet(self, packet):
        if not self.is_running:
            return
            
        self.packet_count += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport, dport = "N/A", "N/A"
            
            # 1. Protocol Identify
            if TCP in packet:
                protocol = "TCP"
                sport, dport = packet[TCP].sport, packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                sport, dport = packet[UDP].sport, packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = "Other"

            # 2. Domain Resolve
            domain = "Unknown"
            if dst_ip in ["198.51.100.1", "203.0.113.1", "192.0.2.1"]:
                domain = "⚠️ Simulated Malicious IP"
            else:
                try:
                    domain = socket.gethostbyaddr(dst_ip)[0]
                except:
                    if dst_ip.startswith("142.250") or dst_ip.startswith("35.190"):
                        domain = "Google / YouTube"
                    elif dst_ip.startswith("104.18"):
                        domain = "Cloudflare"
                    else:
                        domain = "Unknown Server"

            # 3. App Name
            if protocol == "ICMP":
                app_name = "System Ping / ICMP"
            else:
                app_name = self._get_process_name(sport) if sport != "N/A" else "Unknown"
            
            # 4. AI Logic
            prediction = "Benign"
            severity = "Low"
            
            if "Simulated Malicious" in domain:
                prediction = "Suspicious"
                severity = "High"
            elif protocol == "ICMP":
                prediction = "Suspicious" 
                severity = "Medium"
            elif app_name == "Unknown" and protocol == "TCP":
                known_keywords = ["Google", "YouTube", "Cloudflare", "Facebook", "Microsoft", "Apple", "Amazon"]
                is_known = any(kw.lower() in domain.lower() for kw in known_keywords)
                
                if not is_known and not dst_ip.startswith("192.168") and not dst_ip.startswith("10."):
                    prediction = "Suspicious"
                    severity = "Medium"

            # 5. Attack Type Logic
            attack_type = "Normal Traffic"
            if "Simulated Malicious" in domain:
                attack_type = "Malicious IP Connection"
            elif protocol == "ICMP":
                attack_type = "ICMP Ping Sweep"
            elif prediction == "Suspicious" and app_name == "Unknown":
                attack_type = "Unknown Port Connection"

            packet_info = {
                "src": src_ip,
                "dst": dst_ip,
                "sport": sport,
                "dport": dport,
                "domain": domain,
                "app": app_name,
                "protocol": protocol,
                "prediction": prediction,
                "severity": severity,
                "attack_type": attack_type
            }
            
            self.recent_packets.append(packet_info)
            if len(self.recent_packets) > 50:
                self.recent_packets.pop(0)

monitor_instance = LiveMonitor()