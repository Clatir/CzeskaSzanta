from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class TLSFingerprint(BaseFingerprint):
    protocol_name = "TLS"

    def detect(self, packet):
        metadata = {}

        if "TLS" in packet.layers or "SSL" in packet.layers:
            try:
                tls = packet.tls
                metadata["version"] = getattr(tls, "record_version", None)
                metadata["cipher"] = getattr(tls, "handshake_ciphersuite", None)
                metadata["sni"] = getattr(tls, "handshake_extensions_server_name", None)
            except:
                pass

            return 0.9, True, metadata

        raw = str(packet)
        if "Client Hello" in raw:
            return 0.4, True, {}

        return 0.0, False, {}