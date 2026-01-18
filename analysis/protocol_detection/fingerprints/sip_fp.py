from analysis.protocol_detection.base_fingerprint import BaseFingerprint
from analysis.protocol_detection.fingerprints._fp_utils import get_tcp_text_payload

class SIPFingerprint(BaseFingerprint):
    protocol_name = "SIP"

    SIP_METHODS = ("INVITE", "REGISTER", "ACK", "BYE", "CANCEL", "OPTIONS", "MESSAGE", "INFO", "PRACK", "UPDATE")

    def detect(self, pkt):
        try:
            if hasattr(pkt, "sip"):
                md = {}
                try:
                    md["call_id"] = getattr(pkt.sip, "call_id", None)
                    md["from"] = getattr(pkt.sip, "from_user", None)
                    md["to"] = getattr(pkt.sip, "to_user", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "sip"}

            s = get_tcp_text_payload(pkt, limit=1024)
            if not s:
                return 0.0, False, None
            up = s.upper()

            if up.startswith("SIP/2.0"):
                return 0.9, True, {"first_line": s.splitlines()[0][:120]}
            for m in self.SIP_METHODS:
                if up.startswith(m + " "):
                    return 0.9, True, {"method": m, "first_line": s.splitlines()[0][:120]}

            return 0.0, False, None
        except:
            return 0.0, False, None
