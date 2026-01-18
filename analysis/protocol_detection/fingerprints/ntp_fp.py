from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class NTPFingerprint(BaseFingerprint):
    protocol_name = "NTP"

    def detect(self, pkt):
        try:
            if not hasattr(pkt, "udp"):
                return 0.0, False, None

            # NTP = UDP payload length == 48 bytes (classic)
            payload_len = int(pkt.udp.length)
            if payload_len == 48:
                return 0.8, True, {
                    "udp_length": payload_len
                }

            return 0.0, False, None
        except:
            return 0.0, False, None
