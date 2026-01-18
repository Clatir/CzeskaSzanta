from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class ARPFingerprint(BaseFingerprint):
    protocol_name = "ARP"

    def detect(self, pkt):
        try:
            if hasattr(pkt, "arp"):
                md = {}
                try:
                    md["src_ip"] = pkt.arp.src_proto_ipv4
                    md["dst_ip"] = pkt.arp.dst_proto_ipv4
                except:
                    pass
                return 0.9, True, md or {"detected": "arp"}
            return 0.0, False, None
        except:
            return 0.0, False, None