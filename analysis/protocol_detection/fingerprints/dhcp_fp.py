from analysis.protocol_detection.base_fingerprint import BaseFingerprint
from analysis.protocol_detection.fingerprints._fp_utils import get_udp_payload_len

class DHCPFingerprint(BaseFingerprint):
    protocol_name = "DHCP"

    def detect(self, pkt):
        try:
            # Najpewniej: tshark rozpoznaje warstwę dhcp/bootp
            if hasattr(pkt, "dhcp") or hasattr(pkt, "bootp"):
                md = {}
                try:
                    md["msg_type"] = getattr(pkt.dhcp, "option_dhcp", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "dhcp/bootp"}

            # fallback: BOOTP/DHCP ma zwykle spory payload (>= 240 B w klasycznym formacie)
            ln = get_udp_payload_len(pkt)
            if ln is not None and ln >= 240:
                return 0.4, False, {"hint": "udp_len>=240"}
            return 0.0, False, None
        except:
            return 0.0, False, None
