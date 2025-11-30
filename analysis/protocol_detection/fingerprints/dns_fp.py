from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class DNSFingerprint(BaseFingerprint):
    protocol_name = "DNS"

    def detect(self, packet):
        metadata = {}

        if "DNS" in packet.layers:
            dns = packet.dns
            metadata["query"] = getattr(dns, "qry_name", None)
            metadata["type"] = getattr(dns, "qry_type", None)
            return 0.95, True, metadata

        raw = str(packet)
        if "Standard query" in raw or "A?" in raw or "AAAA?" in raw:
            return 0.4, True, {}

        return 0.0, False, {}