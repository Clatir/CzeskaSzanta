def normalize_flow(ip1, port1, ip2, port2, l4_proto):
    a = (ip1, int(port1))
    b = (ip2, int(port2))

    x, y = (a, b) if a <= b else (b, a)

    return f"{l4_proto}:{x[0]}:{x[1]}-{y[0]}:{y[1]}"