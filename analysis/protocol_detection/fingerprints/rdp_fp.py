from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class RDPFingerprint(BaseFingerprint):
    protocol_name = "RDP"

    def detect(self, pkt):
        try:
            # Najpewniejsze: tshark rozpoznał RDP / TPKT / COTP
            if hasattr(pkt, "rdp") or hasattr(pkt, "tpkt") or hasattr(pkt, "cotp"):
                md = {}
                try:
                    if hasattr(pkt, "tpkt"):
                        md["tpkt_len"] = getattr(pkt.tpkt, "length", None)
                    if hasattr(pkt, "rdp"):
                        md["security"] = getattr(pkt.rdp, "security_protocol", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "rdp"}

            # Fallback: fingerprint binarny TPKT
            if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
                raw = pkt.tcp.payload.replace(":", "")
                if len(raw) >= 8:
                    b = bytes.fromhex(raw[:8])
                    if b[0] == 0x03 and b[1] == 0x00:
                        return 0.6, False, {"hint": "tpkt_header"}

            return 0.0, False, None
        except:
            return 0.0, False, None