from analysis.protocol_detection.base_fingerprint import BaseFingerprint
from analysis.protocol_detection.fingerprints._fp_utils import get_tcp_text_payload

class AMQPFingerprint(BaseFingerprint):
    protocol_name = "AMQP"

    def detect(self, pkt):
        try:
            if hasattr(pkt, "amqp"):
                md = {}
                try:
                    md["class"] = getattr(pkt.amqp, "class", None)
                    md["method"] = getattr(pkt.amqp, "method", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "amqp"}

            # AMQP handshake zaczyna się od "AMQP\0\0\9\1" (binarnie)
            # pyshark w payload jako hex → sprawdzamy bytes prefix
            if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
                raw = pkt.tcp.payload.replace(":", "")
                b = bytes.fromhex(raw)
                if b.startswith(b"AMQP"):
                    return 0.9, True, {"handshake": "AMQP"}
            return 0.0, False, None
        except:
            return 0.0, False, None
