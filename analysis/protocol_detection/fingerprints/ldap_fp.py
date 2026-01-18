from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class LDAPFingerprint(BaseFingerprint):
    protocol_name = "LDAP"

    def detect(self, pkt):
        try:
            if hasattr(pkt, "ldap"):
                md = {}
                try:
                    md["message_id"] = getattr(pkt.ldap, "message_id", None)
                    md["protocol_op"] = getattr(pkt.ldap, "protocol_op", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "ldap"}
            return 0.0, False, None
        except:
            return 0.0, False, None
