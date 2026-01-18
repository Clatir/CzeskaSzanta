def get_tcp_text_payload(pkt, limit=2048):
    try:
        if not hasattr(pkt, "tcp"):
            return None
        if not hasattr(pkt.tcp, "payload"):
            return None
        raw = pkt.tcp.payload.replace(":", "")
        b = bytes.fromhex(raw)
        return b[:limit].decode(errors="ignore")
    except:
        return None


def get_udp_payload_len(pkt):
    try:
        if not hasattr(pkt, "udp"):
            return None
        if hasattr(pkt.udp, "payload"):
            raw = pkt.udp.payload.replace(":", "")
            return len(bytes.fromhex(raw))
        if hasattr(pkt.udp, "length"):
            return int(pkt.udp.length)
        return None
    except:
        return None
