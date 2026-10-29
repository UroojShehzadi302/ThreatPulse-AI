import threading
import time
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, IP, TCP, UDP, ICMP
import socket
import psutil
from ai_engine.live_predictor import predictor_instance
from live_monitor.flow_features import FlowTable, proto_name

class LiveMonitor:
    def __init__(self):
        self.is_running = False
        self.packet_count = 0
        self.flows_analyzed = 0
        self.attack_count = 0
        self.recent_flows = []
        self.thread = None
        self.classifier_thread = None
        self.flow_table = FlowTable()
        self.lock = threading.Lock()
        self.domain_cache = {}
        self.pending_lookups = set()
        self.resolver = ThreadPoolExecutor(max_workers=4)
        self.port_owners = {}

    @property
    def model_status(self):
        if predictor_instance.is_ready:
            return "Random Forest loaded"
        if predictor_instance.error:
            return f"Model error: {predictor_instance.error}"
        return "Loading model..."

    def start(self):
        if not self.is_running:
            self.is_running = True
            self.packet_count = 0
            self.flows_analyzed = 0
            self.attack_count = 0
            self.recent_flows = []
            self.flow_table = FlowTable()
            self.thread = threading.Thread(target=self._capture_packets)
            self.thread.daemon = True
            self.thread.start()
            self.classifier_thread = threading.Thread(target=self._classify_loop)
            self.classifier_thread.daemon = True
            self.classifier_thread.start()

    def stop(self):
        self.is_running = False

    def _capture_packets(self):
        sniff(prn=self._process_packet, stop_filter=lambda x: not self.is_running, store=False)

    def _load_port_owners(self):
        # One connection-table snapshot per batch; querying it per flow is slow on Windows
        owners = {}
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid and conn.laddr.port not in owners:
                    owners[conn.laddr.port] = conn.pid
        except:
            pass
        self.port_owners = owners

    def _get_process_name(self, local_port):
        try:
            pid = self.port_owners.get(local_port)
            if pid:
                return psutil.Process(pid).name()
        except:
            pass
        return "Unknown"

    def _resolve_domain(self, dst_ip):
        if dst_ip in self.domain_cache:
            return self.domain_cache[dst_ip]

        if dst_ip in ["198.51.100.1", "203.0.113.1", "192.0.2.1"]:
            self.domain_cache[dst_ip] = "⚠️ Simulated Malicious IP"
            return self.domain_cache[dst_ip]

        # Failed reverse lookups take ~5s on Windows, so never make the classifier wait for one
        if dst_ip not in self.pending_lookups:
            self.pending_lookups.add(dst_ip)
            self.resolver.submit(self._lookup_domain, dst_ip)
        return "Resolving..."

    def _lookup_domain(self, dst_ip):
        try:
            domain = socket.gethostbyaddr(dst_ip)[0]
        except:
            if dst_ip.startswith("142.250") or dst_ip.startswith("35.190"):
                domain = "Google / YouTube"
            elif dst_ip.startswith("104.18"):
                domain = "Cloudflare"
            else:
                domain = "Unknown Server"

        with self.lock:
            self.domain_cache[dst_ip] = domain
            self.pending_lookups.discard(dst_ip)
            for flow_info in self.recent_flows:
                if flow_info["dst"] == dst_ip:
                    flow_info["domain"] = domain

    def _process_packet(self, packet):
        if not self.is_running:
            return

        self.packet_count += 1

        if IP not in packet:
            return

        ip = packet[IP]
        now = float(packet.time)
        tcp_info, icmp_type, payload = None, None, b''
        sport, dport = 0, 0

        if TCP in packet:
            seg = packet[TCP]
            sport, dport = seg.sport, seg.dport
            tcp_info = (int(seg.flags), seg.seq, seg.window)
            payload = bytes(seg.payload)
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
            payload = bytes(packet[UDP].payload)
        elif ICMP in packet:
            icmp_type = packet[ICMP].type

        with self.lock:
            flow, forward = self.flow_table.get_or_create(proto_name(ip.proto), ip.src, ip.dst, sport, dport, now)
            flow.add_packet(forward, ip.len or len(ip), ip.ttl, now, tcp=tcp_info, payload=payload, icmp_type=icmp_type)

    def _classify_loop(self):
        predictor_instance.load()
        while self.is_running:
            time.sleep(1)
            self._classify_ready_flows()
        # Flush whatever is left so the last flows still get a verdict
        self._classify_ready_flows(flush=True)

    def _classify_ready_flows(self, flush=False):
        with self.lock:
            now = time.time()
            if flush:
                expired, active = list(self.flow_table.flows.values()), []
                self.flow_table.flows.clear()
            else:
                expired, active = self.flow_table.collect_ready(now)

            batch, feature_rows = [], []
            # Expired flows are featurised one by one so each sees the connections that preceded it
            for flow in expired:
                feature_rows.append(flow.features(self.flow_table.history, predictor_instance.ct_state_ttl))
                batch.append((flow, True))
                self.flow_table.record(flow)
            for flow in active:
                feature_rows.append(flow.features(self.flow_table.history, predictor_instance.ct_state_ttl))
                batch.append((flow, False))
                flow.classified_at = now

        if not batch or not predictor_instance.is_ready:
            return

        results = predictor_instance.predict(feature_rows)
        self._load_port_owners()
        for (flow, is_final), features, (label, attack_prob) in zip(batch, feature_rows, results):
            self._publish(flow, features, label, attack_prob, is_final)

    def _publish(self, flow, features, label, attack_prob, is_final):
        if label == "Attack":
            severity = "High" if attack_prob >= 0.9 else "Medium"
            attack_type = "Malicious Flow (RF)"
        else:
            severity = "Low"
            attack_type = "Normal Traffic"

        protocol = flow.proto.upper() if flow.proto != 'any' else "Other"
        if protocol == "ICMP":
            app_name = "System Ping / ICMP"
        else:
            app_name = self._get_process_name(flow.sport) if flow.sport else "Unknown"

        flow_info = {
            "id": f"{flow.key}-{flow.start}",
            "time": flow.last,
            "src": flow.src,
            "dst": flow.dst,
            "sport": flow.sport or "N/A",
            "dport": flow.dport or "N/A",
            "domain": self._resolve_domain(flow.dst),
            "app": app_name,
            "protocol": protocol,
            "service": features['service'],
            "state": features['state'],
            "packets": features['Spkts'] + features['Dpkts'],
            "bytes": features['sbytes'] + features['dbytes'],
            "prediction": label,
            "confidence": round((attack_prob if label == "Attack" else 1 - attack_prob) * 100, 1),
            "severity": severity,
            "attack_type": attack_type,
            "active": not is_final
        }

        with self.lock:
            # A long-lived flow may be re-scored; replace its earlier verdict instead of double counting
            if flow.last_label is None:
                self.flows_analyzed += 1
            elif flow.last_label == "Attack":
                self.attack_count -= 1
            if label == "Attack":
                self.attack_count += 1
            flow.last_label = label

            self.recent_flows = [f for f in self.recent_flows if f["id"] != flow_info["id"]]

            flow_info["domain"] = self.domain_cache.get(flow.dst, flow_info["domain"])
            self.recent_flows.append(flow_info)
            # Keep the last 50 of each verdict so busy normal traffic can't push attacks out of view
            same_label = [f for f in self.recent_flows if f["prediction"] == label]
            if len(same_label) > 50:
                self.recent_flows.remove(same_label[0])

monitor_instance = LiveMonitor()
