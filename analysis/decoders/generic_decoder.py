from analysis.decoders.http_decoder import decode_http
from analysis.decoders.dns_decoder import decode_dns
from analysis.decoders.tls_decoder import decode_tls

SUPPORTED_PROTOCOLS = {
    "HTTP": decode_http,
    "DNS": decode_dns,
    "TLS": decode_tls
}

def decode_all_l7(pcap_path, present_protocols):
    results = {
        "http": [],
        "dns": [],
        "tls": []
    }

    extracted_files = []

    for proto, decoder in SUPPORTED_PROTOCOLS.items():
        if proto in present_protocols:
            result = decoder(pcap_path)

            if result.get("success"):
                if result.get("entries"):
                    results[proto.lower()] = result["entries"]

                if result.get("extracted_files"):
                    extracted_files.extend(result["extracted_files"])

    return {
        "success": True,
        "l7_data": results,
        "extracted_files": extracted_files
    }
