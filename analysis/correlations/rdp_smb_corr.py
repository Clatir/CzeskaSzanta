RDP_PORT = 3389
SMB_PORTS = {445, 139}


def _build_corr(cid, severity, description, evidence=None):
    return {
        "id": cid,
        "severity": severity,
        "description": description,
        "protocols": ["RDP", "SMB"],
        "evidence": evidence or {},
    }


def _pair_key(a, b):
    if not a or not b:
        return None
    return tuple(sorted((a, b)))


def correlate_rdp_smb_exfil(report_data):
    correlations = []

    sessions_data = report_data.get("sessions", {})
    sessions = sessions_data.get("sessions", []) or []

    if not sessions:
        return correlations

    rdp_by_pair = {}
    smb_by_pair = {}

    for sess in sessions:
        proto = sess.get("protocol")
        if proto != "TCP":
            continue

        src_ip = sess.get("src_ip")
        dst_ip = sess.get("dst_ip")
        dst_port = sess.get("dst_port")

        pair = _pair_key(src_ip, dst_ip)
        if pair is None:
            continue

        if dst_port == RDP_PORT:
            rdp_by_pair.setdefault(pair, []).append(sess)

        if dst_port in SMB_PORTS:
            smb_by_pair.setdefault(pair, []).append(sess)

    # Szukamy par hostów, dla których istnieje zarówno RDP, jak i SMB
    candidate_pairs = set(rdp_by_pair.keys()) & set(smb_by_pair.keys())

    for pair in sorted(candidate_pairs):
        rdp_sess = rdp_by_pair.get(pair, [])
        smb_sess = smb_by_pair.get(pair, [])

        large_smb = [
            s for s in smb_sess
            if s.get("bytes_total", 0) > 10_000_000  # ~10MB
        ]

        if not large_smb:
            # jeżeli nie ma dużych sesji SMB, potraktujmy jako słabszy sygnał
            if len(smb_sess) >= 3:
                correlations.append(
                    _build_corr(
                        "CORR-002",
                        "medium",
                        "RDP + wiele sesji SMB między tymi samymi hostami (potencjalny lateral movement).",
                        {
                            "hosts": {
                                "a": pair[0],
                                "b": pair[1],
                            },
                            "rdp_sessions": [s.get("id") for s in rdp_sess],
                            "smb_sessions": [s.get("id") for s in smb_sess],
                        },
                    )
                )
            continue

        # Jeżeli są duże sesje SMB po RDP, traktujemy to jako silniejszy scenariusz
        correlations.append(
            _build_corr(
                "CORR-003",
                "high",
                "RDP + duże transfery SMB między tymi samymi hostami (potencjalna exfiltracja lub kopiowanie plików po zdalnym dostępie).",
                {
                    "hosts": {
                        "a": pair[0],
                        "b": pair[1],
                    },
                    "rdp_sessions": [s.get("id") for s in rdp_sess],
                    "smb_large_sessions": [
                        {
                            "id": s.get("id"),
                            "bytes_total": s.get("bytes_total"),
                            "packet_count": s.get("packet_count"),
                        }
                        for s in large_smb
                    ],
                },
            )
        )

    return correlations
