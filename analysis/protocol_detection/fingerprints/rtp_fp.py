from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class RTPFingerprint(BaseFingerprint):
    protocol_name = "RTP"

    def detect(self, pkt):
        try:
            if hasattr(pkt, "rtp"):
                md = {}
                try:
                    md["pt"] = getattr(pkt.rtp, "p_type", None)
                    md["ssrc"] = getattr(pkt.rtp, "ssrc", None)
                except:
                    pass
                return 0.9, True, md or {"detected": "rtp"}
            return 0.0, False, None
        except:
            return 0.0, False, None