from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class FTPFingerprint(BaseFingerprint):
    protocol_name = "FTP"

    FTP_CMDS = (
        "USER", "PASS", "LIST", "RETR", "STOR",
        "CWD", "PWD", "PASV", "PORT", "QUIT"
    )

    def detect(self, pkt):
        try:
            if not hasattr(pkt, "tcp"):
                return 0.0, False, None

            payload = bytes.fromhex(pkt.tcp.payload.replace(":", "")).decode(errors="ignore")
            up = payload.upper()

            for cmd in self.FTP_CMDS:
                if up.startswith(cmd):
                    return 1.0, True, {
                        "command": cmd,
                        "sample": payload[:80]
                    }

            return 0.1, False, None
        except:
            return 0.0, False, None
