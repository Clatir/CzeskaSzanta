import importlib
import pkgutil
import pyshark

from analysis.protocol_detection.fingerprints import __path__ as fp_path

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


def detect_protocols(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    fingerprints = load_fingerprint_classes()

    per_protocol = {}
    confidence = {}
    details = {}
    flow_map = {}

    total_packets = 0

    for fp in fingerprints:
        proto = fp.protocol_name
        per_protocol[proto] = 0
        confidence[proto] = 0.0
        details[proto] = {
            "ports": [],
            "metadata_samples": []
        }
        flow_map[proto] = []

    for pkt in cap:
        total_packets += 1 

        for fp in fingerprints:
            proto = fp.protocol_name
            score, match, metadata = fp.detect(pkt)

            # global scoring
            confidence[proto] += score

            if match:
                per_protocol[proto] += 1
                details[proto]["metadata_samples"].append(metadata)

                try:
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    sport = pkt[pkt.transport_layer].srcport
                    dport = pkt[pkt.transport_layer].dstport

                    flow_map[proto].append({
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": sport,
                        "dst_port": dport
                    })

                    if dport not in details[proto]["ports"]:
                        details[proto]["ports"].append(dport)

                except:
                    pass

    cap.close()

    for proto in confidence:
        if per_protocol[proto] > 0:
            confidence[proto] = min(1.0, confidence[proto] / per_protocol[proto])
        else:
            confidence[proto] = 0.0

    detected = [p for p, cnt in per_protocol.items() if cnt > 0]

    return {
        "detected": detected,
        "per_protocol": per_protocol,
        "confidence": confidence,
        "details": details,
        "flow_map": flow_map,
        "total_packets": total_packets
    }
