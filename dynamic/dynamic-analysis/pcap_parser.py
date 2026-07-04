"""
Parses the captured .pcap and pulls out the indicators that matter for
C2 identification: DNS queries, TLS SNI hostnames (works even for
encrypted traffic, since SNI is sent in plaintext during the TLS
handshake), and raw destination IPs/ports.

Requires `tshark` installed on the host (comes with Wireshark).
"""

import pyshark

# IPs to ignore — emulator loopback / gateway / local DNS noise
IGNORE_IPS = {"10.0.2.15", "10.0.2.2", "10.0.2.3", "127.0.0.1"}

# Domains Android itself contacts in the background regardless of which
# app is running (connectivity checks, time sync, Play Services heartbeat).
# These are OS noise, not app behaviour, and would otherwise show up as
# false-positive "unexplained connections" for every single sample tested.
IGNORE_DOMAINS = {
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "clients.google.com",
    "www.google.com",
    "android.clients.google.com",
    "play.googleapis.com",
    "firebaseinstallations.googleapis.com",
    "mtalk.google.com",
    "time.android.com",
    "pool.ntp.org",
}


def parse_pcap(pcap_path):
    domains = set()
    dest_ips = set()
    connections = []  # list of {ip, port, domain}

    cap = pyshark.FileCapture(pcap_path, display_filter="dns || tls.handshake.type == 1")

    for pkt in cap:
        try:
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                name = pkt.dns.qry_name
                if name not in IGNORE_DOMAINS:
                    domains.add(name)

            if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                sni = pkt.tls.handshake_extensions_server_name
                if sni in IGNORE_DOMAINS:
                    continue
                domains.add(sni)

                dst_ip = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else None
                dst_port = getattr(pkt.tcp, "dstport", None) if hasattr(pkt, "tcp") else None

                if dst_ip and dst_ip not in IGNORE_IPS:
                    dest_ips.add(dst_ip)
                    connections.append({"ip": dst_ip, "port": dst_port, "domain": sni})

        except AttributeError:
            continue

    cap.close()

    return {
        "domains": sorted(domains),
        "dest_ips": sorted(dest_ips),
        "connections": connections,
    }