from analysis.protocol_detection.base_fingerprint import BaseFingerprint

class SMBFingerprint(BaseFingerprint):
    protocol_name = "SMB"

    def detect(self, pkt):
        try:
            # tshark może rozpoznać smb lub smb2
            if hasattr(pkt, "smb2"):
                md = {}
                try:
                    md["cmd"] = getattr(pkt.smb2, "cmd", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "smb2"}

            if hasattr(pkt, "smb"):
                md = {}
                try:
                    md["cmd"] = getattr(pkt.smb, "cmd", None)
                except:
                    pass
                return 0.95, True, md or {"detected": "smb"}

            # fallback: SMB signature w payload (0xFF 'SMB' albo 'FE' 'SMB')
            if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
                raw = pkt.tcp.payload.replace(":", "")
                b = bytes.fromhex(raw)
                if len(b) >= 4 and (b[0] == 0xFF and b[1:4] == b"SMB"):
                    return 0.9, True, {"signature": "FFSMB"}
                if len(b) >= 4 and (b[0] == 0xFE and b[1:4] == b"SMB"):
                    return 0.9, True, {"signature": "FESMB"}

            return 0.0, False, None
        except:
            return 0.0, False, None