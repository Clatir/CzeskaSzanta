from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class HTTPFingerprint(BaseFingerprint):
    protocol_name = "HTTP"

    def detect(self, packet):
        metadata = {}

        if "HTTP" in packet.layers:
            layer = packet.http
            metadata["method"] = getattr(layer, "request_method", None)
            metadata["host"] = getattr(layer, "host", None)
            metadata["uri"] = getattr(layer, "request_uri", None)
            metadata["content_type"] = getattr(layer, "content_type", None)
            return 0.95, True, metadata

        raw = str(packet)
        if "HTTP/1." in raw or "GET /" in raw or "POST /" in raw:
            return 0.6, True, {}

        return 0.0, False, {}