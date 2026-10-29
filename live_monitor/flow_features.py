import statistics
from collections import deque

# Server port -> UNSW-NB15 service name (anything else is '-')
SERVICE_PORTS = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 25: 'smtp', 53: 'dns',
    67: 'dhcp', 68: 'dhcp', 80: 'http', 8080: 'http', 110: 'pop3',
    161: 'snmp', 162: 'snmp', 194: 'irc', 6667: 'irc', 443: 'ssl',
    1812: 'radius', 1813: 'radius',
}

PROTO_NUMBERS = {6: 'tcp', 17: 'udp', 1: 'icmp', 2: 'igmp', 41: 'ipv6', 47: 'gre', 50: 'esp',
                 89: 'ospf', 103: 'pim', 132: 'sctp'}

# TCP flag bits
FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10


class _Direction:
    def __init__(self):
        self.bytes = 0
        self.pkts = 0
        self.ttl = 0
        self.win = 0
        self.base_seq = 0
        self.times = []
        self.seen_segments = set()
        self.loss = 0


class Flow:
    """Bidirectional flow keyed on the initiator's 5-tuple."""

    def __init__(self, key, proto, src, dst, sport, dport, now):
        self.key = key
        self.proto = proto
        self.src, self.dst = src, dst
        self.sport, self.dport = sport, dport
        self.start = now
        self.last = now
        self.fwd = _Direction()
        self.bwd = _Direction()
        self.syn_time = None
        self.synack_time = None
        self.ack_time = None
        self.fin_seen = False
        self.rst_seen = False
        self.icmp_type = None
        self.http_requests = 0
        self.res_bdy_len = 0
        self.ftp_user = False
        self.ftp_pass = False
        self.classified_at = None
        self.last_label = None

    @property
    def service(self):
        return SERVICE_PORTS.get(self.dport) or SERVICE_PORTS.get(self.sport) or '-'

    @property
    def finished(self):
        return self.fin_seen or self.rst_seen

    def add_packet(self, forward, ip_len, ttl, now, tcp=None, payload=b'', icmp_type=None):
        d = self.fwd if forward else self.bwd
        d.bytes += ip_len
        d.pkts += 1
        d.times.append(now)
        if d.pkts == 1:
            d.ttl = ttl
        self.last = now

        if icmp_type is not None and self.icmp_type is None:
            self.icmp_type = icmp_type

        if tcp is not None:
            flags, seq, window = tcp
            if d.pkts == 1:
                d.win = min(window, 255)
                d.base_seq = seq
            if flags & SYN and not flags & ACK and forward and self.syn_time is None:
                self.syn_time = now
            elif flags & SYN and flags & ACK and not forward and self.synack_time is None:
                self.synack_time = now
            elif flags & ACK and forward and self.synack_time is not None and self.ack_time is None:
                self.ack_time = now
            if flags & FIN:
                self.fin_seen = True
            if flags & RST:
                self.rst_seen = True
            if payload:
                segment = (seq, len(payload))
                if segment in d.seen_segments:
                    d.loss += 1
                else:
                    d.seen_segments.add(segment)

        if payload:
            self._inspect_payload(forward, payload)

    def _inspect_payload(self, forward, payload):
        service = self.service
        if service == 'http':
            if forward and payload[:5] in (b'GET /', b'POST ', b'HEAD ', b'PUT /'):
                self.http_requests += 1
            elif not forward and payload.startswith(b'HTTP/'):
                for line in payload.split(b'\r\n'):
                    if line.lower().startswith(b'content-length:'):
                        try:
                            self.res_bdy_len += int(line.split(b':', 1)[1].strip())
                        except ValueError:
                            pass
                        break
        elif service == 'ftp' and forward:
            if payload.startswith(b'USER '):
                self.ftp_user = True
            elif payload.startswith(b'PASS '):
                self.ftp_pass = True

    def state(self):
        """Approximates the Argus connection state labels used in UNSW-NB15."""
        if self.proto == 'tcp':
            if self.rst_seen:
                return 'RST'
            if self.fin_seen:
                return 'FIN'
            if self.syn_time is not None and self.synack_time is None:
                return 'REQ'
            if self.bwd.pkts > 0:
                return 'CON'
            return 'INT'
        if self.proto == 'icmp':
            if self.icmp_type == 8:
                return 'ECO'
            if self.icmp_type == 0:
                return 'ECR'
            return 'URH'
        return 'CON' if self.bwd.pkts > 0 else 'INT'

    @staticmethod
    def _intervals_ms(times):
        return [(b - a) * 1000 for a, b in zip(times, times[1:])]

    def features(self, history, ct_state_ttl_lookup):
        dur = max(self.last - self.start, 0.0)
        f, b = self.fwd, self.bwd
        state = self.state()
        service = self.service

        s_int = self._intervals_ms(f.times)
        d_int = self._intervals_ms(b.times)

        synack = (self.synack_time - self.syn_time) if self.syn_time and self.synack_time else 0.0
        ackdat = (self.ack_time - self.synack_time) if self.synack_time and self.ack_time else 0.0

        # UNSW-NB15 connection counts over the last 100 connections (current one included)
        recent = list(history)
        ct_srv_src = 1 + sum(1 for c in recent if c['service'] == service and c['src'] == self.src)
        ct_srv_dst = 1 + sum(1 for c in recent if c['service'] == service and c['dst'] == self.dst)
        ct_dst_ltm = 1 + sum(1 for c in recent if c['dst'] == self.dst)
        ct_src_ltm = 1 + sum(1 for c in recent if c['src'] == self.src)
        ct_src_dport_ltm = 1 + sum(1 for c in recent if c['src'] == self.src and c['dport'] == self.dport)
        ct_dst_sport_ltm = 1 + sum(1 for c in recent if c['dst'] == self.dst and c['sport'] == self.sport)
        ct_dst_src_ltm = 1 + sum(1 for c in recent if c['src'] == self.src and c['dst'] == self.dst)

        return {
            'proto': self.proto,
            'state': state,
            'service': service,
            'dur': dur,
            'sbytes': f.bytes,
            'dbytes': b.bytes,
            'sttl': f.ttl,
            'dttl': b.ttl,
            'sloss': f.loss,
            'dloss': b.loss,
            'Sload': (f.bytes * 8 / dur) if dur > 0 else 0.0,
            'Dload': (b.bytes * 8 / dur) if dur > 0 else 0.0,
            'Spkts': f.pkts,
            'Dpkts': b.pkts,
            'swin': f.win,
            'dwin': b.win,
            'stcpb': f.base_seq,
            'dtcpb': b.base_seq,
            'smeansz': int(f.bytes / f.pkts) if f.pkts else 0,
            'dmeansz': int(b.bytes / b.pkts) if b.pkts else 0,
            'trans_depth': self.http_requests,
            'res_bdy_len': self.res_bdy_len,
            'Sjit': statistics.pstdev(s_int) if len(s_int) > 1 else 0.0,
            'Djit': statistics.pstdev(d_int) if len(d_int) > 1 else 0.0,
            'Sintpkt': statistics.mean(s_int) if s_int else 0.0,
            'Dintpkt': statistics.mean(d_int) if d_int else 0.0,
            'tcprtt': synack + ackdat,
            'synack': synack,
            'ackdat': ackdat,
            'is_sm_ips_ports': int(self.src == self.dst and self.sport == self.dport),
            'ct_state_ttl': ct_state_ttl_lookup(state, f.ttl, b.ttl),
            'ct_flw_http_mthd': self.http_requests,
            'is_ftp_login': int(self.ftp_user and self.ftp_pass),
            'ct_srv_src': ct_srv_src,
            'ct_srv_dst': ct_srv_dst,
            'ct_dst_ltm': ct_dst_ltm,
            'ct_src_ltm': ct_src_ltm,
            'ct_src_dport_ltm': ct_src_dport_ltm,
            'ct_dst_sport_ltm': ct_dst_sport_ltm,
            'ct_dst_src_ltm': ct_dst_src_ltm,
        }


class FlowTable:
    """Groups packets into flows and decides when each flow is ready for the model."""

    def __init__(self, idle_timeout=3.0, active_timeout=10.0, history_size=100):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.flows = {}
        self.history = deque(maxlen=history_size)

    def get_or_create(self, proto, src, dst, sport, dport, now):
        """Returns (flow, is_forward). The first packet seen defines the flow's source."""
        key = (proto, src, dst, sport, dport)
        if key in self.flows:
            return self.flows[key], True
        reverse = (proto, dst, src, dport, sport)
        if reverse in self.flows:
            return self.flows[reverse], False
        flow = Flow(key, proto, src, dst, sport, dport, now)
        self.flows[key] = flow
        return flow, True

    def collect_ready(self, now, grace=0.5):
        """Returns (expired_flows, active_flows_due_for_reclassification).
        Expired flows are removed from the table and recorded in the connection history."""
        expired, active = [], []
        for key, flow in list(self.flows.items()):
            if (flow.finished and now - flow.last > grace) or now - flow.last > self.idle_timeout:
                expired.append(self.flows.pop(key))
            elif now - (flow.classified_at or flow.start) > self.active_timeout:
                active.append(flow)
        return expired, active

    def record(self, flow):
        self.history.append({
            'src': flow.src, 'dst': flow.dst,
            'sport': flow.sport, 'dport': flow.dport,
            'service': flow.service,
        })


def proto_name(number):
    return PROTO_NUMBERS.get(number, 'any')
