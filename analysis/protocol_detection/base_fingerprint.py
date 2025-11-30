class BaseFingerprint:
    protocol_name = "UNKNOWN"

    def detect(self, packet):
        raise NotImplementedError
