import pyshark

SMTP_CMDS = ("HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", "QUIT", "RSET", "NOOP")


def decode_smtp(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    items = []
    errors = []

    stats = {
        "commands_total": 0,
        "mail_from": 0,
        "rcpt_to": 0,
        "data_seen": 0,
    }

    try:
        for pkt in cap:
            try:
                if not hasattr(pkt, "tcp") or not hasattr(pkt.tcp, "payload"):
                    continue

                raw = pkt.tcp.payload.replace(":", "")
                if not raw:
                    continue

                try:
                    payload = bytes.fromhex(raw).decode(errors="ignore")
                except:
                    continue

                if not payload:
                    continue

                lines = payload.splitlines()
                if not lines:
                    continue

                first = lines[0]
                up = first.upper()

                matched = None
                for cmd in SMTP_CMDS:
                    if up.startswith(cmd):
                        matched = cmd
                        break

                if not matched:
                    continue

                stats["commands_total"] += 1
                if matched == "MAIL FROM":
                    stats["mail_from"] += 1
                if matched == "RCPT TO":
                    stats["rcpt_to"] += 1
                if matched == "DATA":
                    stats["data_seen"] += 1

                src = dst = sport = dport = None
                ts = None
                try:
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                    sport = pkt.tcp.srcport
                    dport = pkt.tcp.dstport
                    ts = pkt.sniff_time.isoformat()
                except:
                    pass

                arg = first[len(matched):].strip() if len(first) > len(matched) else ""

                items.append({
                    "timestamp": ts,
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "command": matched,
                    "arg": arg
                })
            except:
                continue
    except Exception as e:
        errors.append(str(e))
    finally:
        cap.close()

    return {
        "success": len(errors) == 0,
        "protocol": "SMTP",
        "stats": stats,
        "items": items,
        "errors": errors
    }
