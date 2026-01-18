from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class MQTTFingerprint(BaseFingerprint):
    protocol_name = "MQTT"

    def detect(self, pkt):
        try:
            if hasattr(pkt, "mqtt"):
                md = {}
                try:
                    md["msgtype"] = getattr(pkt.mqtt, "msgtype", None)
                    md["clientid"] = getattr(pkt.mqtt, "clientid", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "mqtt"}
            return 0.0, False, None
        except:
            return 0.0, False, None