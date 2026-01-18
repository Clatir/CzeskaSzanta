import pyshark

FTP_CMDS = (
    "USER", "PASS", "LIST", "RETR", "STOR",
    "CWD", "PWD", "PASV", "PORT", "QUIT"
)


def decode_ftp(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    items = []
    errors = []

    stats = {
        "commands_total": 0,
        "user": 0,
        "pass": 0,
        "retr": 0,
        "stor": 0
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
                for cmd in FTP_CMDS:
                    if up.startswith(cmd + " ") or up == cmd:
                        matched = cmd
                        break

                if not matched:
                    continue

                stats["commands_total"] += 1
                if matched == "USER":
                    stats["user"] += 1
                if matched == "PASS":
                    stats["pass"] += 1
                if matched == "RETR":
                    stats["retr"] += 1
                if matched == "STOR":
                    stats["stor"] += 1

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
        "protocol": "FTP",
        "stats": stats,
        "items": items,
        "errors": errors
    }
