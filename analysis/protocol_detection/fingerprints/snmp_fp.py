from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class SNMPFingerprint(BaseFingerprint):
    protocol_name = "SNMP"

    def detect(self, pkt):
        try:
            if hasattr(pkt, "snmp"):
                md = {}
                try:
                    md["version"] = getattr(pkt.snmp, "version", None)
                    md["community"] = getattr(pkt.snmp, "community", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "snmp"}
            return 0.0, False, None
        except:
            return 0.0, False, None
