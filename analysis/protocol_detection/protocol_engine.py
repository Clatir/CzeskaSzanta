import importlib
import pkgutil
import pyshark

from collections import defaultdict
from analysis.protocol_detection.fingerprints import __path__ as fp_path
from analysis.flow_key import normalize_flow

def load_fingerprint_classes():
    modules = []

    for _, module_name, _ in pkgutil.iter_modules(fp_path):
        full = f"analysis.protocol_detection.fingerprints.{module_name}"
        mod = importlib.import_module(full)

        for attr in dir(mod):
            obj = getattr(mod, attr)
            try:
                if hasattr(obj, "protocol_name") and obj.protocol_name != "UNKNOWN":
                    modules.append(obj())
            except:
                pass

    return modules

def _safe_get_flow(pkt):
    try:
        if hasattr(pkt, "ip"):
            src = pkt.ip.src
            dst = pkt.ip.dst
        elif hasattr(pkt, "ipv6"):
            src = pkt.ipv6.src
            dst = pkt.ipv6.dst
        else:
            return None

        l4 = getattr(pkt, "transport_layer", None)
        if not l4:
            return None

        sport = pkt[l4].srcport
        dport = pkt[l4].dstport
        if sport is None or dport is None:
            return None

        return (src, dst, sport, dport, l4)
    except:
        return None


def detect_protocols(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    fingerprints = load_fingerprint_classes()

    per_protocol = {}
    confidence_sum = {}
    confidence = {}
    details = {}
    flow_map = {}

    total_packets = 0

    for fp in fingerprints:
        proto = fp.protocol_name
        per_protocol[proto] = 0
        confidence[proto] = 0.0
        confidence_sum[proto] = 0.0
        details[proto] = {
            "ports": [],
            "metadata_samples": []
        }

    for pkt in cap:
        total_packets += 1 
        flow = _safe_get_flow(pkt)
        flow_key = None

        if flow:
            src, dst, sport, dport, l4 = flow
            flow_key = normalize_flow(src, sport, dst, dport, l4)

            if flow_key not in flow_map:
                flow_map[flow_key] = {
                    "l4": str(l4),
                    "total": 0,
                    "counts": defaultdict(int),
                    "example": {
                        "src_ip": str(src),
                        "dst_ip": str(dst),
                        "src_port": int(sport),
                        "dst_port": int(dport),
                    }
                }
            flow_map[flow_key]["total"] += 1

        for fp in fingerprints:
            proto = fp.protocol_name
            score, match, metadata = fp.detect(pkt)

            if match:
                per_protocol[proto] += 1
                confidence_sum[proto] += score
                details[proto]["metadata_samples"].append(metadata)

                if flow:
                    try:
                        dport_int = int(flow[3])
                        if dport_int not in details[proto]["ports"]:
                            details[proto]["ports"].append(dport_int)
                    except:
                        pass

                if flow_key is not None:
                    flow_map[flow_key]["counts"][proto] += 1

    cap.close()

    for proto in confidence:
        if per_protocol[proto] > 0:
            confidence[proto] = min(1.0, confidence_sum[proto] / per_protocol[proto])
        else:
            confidence[proto] = 0.0

    detected = [p for p, cnt in per_protocol.items() if cnt > 0]

    for fk in list(flow_map.keys()):
        flow_map[fk]["counts"] = dict(flow_map[fk]["counts"])

    return {
        "detected": detected,
        "per_protocol": per_protocol,
        "confidence": confidence,
        "details": details,
        "flow_map": flow_map,
        "total_packets": total_packets
    }
