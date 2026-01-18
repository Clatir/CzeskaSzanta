from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class ICMPFingerprint(BaseFingerprint):
    protocol_name = "ICMP"

    def detect(self, pkt):
        try:
            if hasattr(pkt, "icmp"):
                md = {}
                try:
                    md["type"] = getattr(pkt.icmp, "type", None)
                    md["code"] = getattr(pkt.icmp, "code", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "icmp"}
            return 0.0, False, None
        except:
            return 0.0, False, None