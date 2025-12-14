from analysis.flow_key import normalize_flow

def bind_sessions_to_protocols(sessions_data, protocol_data):
    flow_map = protocol_data.get("flow_map", {})
    sessions = sessions_data.get("sessions", [])

    for sess in sessions:
        try:
            flow_key = normalize_flow(
                sess["src_ip"],
                sess["src_port"],
                sess["dst_ip"],
                sess["dst_port"],
                sess["protocol"]
            )
        except:
            continue

        flow = flow_map.get(flow_key)
        if not flow:
            continue

        counts = flow.get("counts", {})
        total = flow.get("total", 0)

        if not counts or total <= 0:
            continue

        dominant_proto, dominant_hits = max(counts.items(), key=lambda x: x[1])

        sess["l7_protocol"] = dominant_proto
        sess["l7_confidence"] = round(dominant_hits / total, 3)
        sess["l7_candidates"] = counts

    sessions_data["sessions"] = sessions
    return sessions_data
