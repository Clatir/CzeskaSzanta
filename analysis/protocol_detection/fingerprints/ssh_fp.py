from analysis.protocol_detection.base_fingerprint import BaseFingerprint
from analysis.protocol_detection.fingerprints._fp_utils import get_tcp_text_payload

class SSHFingerprint(BaseFingerprint):
    protocol_name = "SSH"

    def detect(self, pkt):
        try:
            s = get_tcp_text_payload(pkt, limit=256)
            if not s:
                return 0.0, False, None
            if s.startswith("SSH-"):
                return 1.0, True, {"banner": s.strip()[:120]}
            return 0.0, False, None
        except:
            return 0.0, False, None
