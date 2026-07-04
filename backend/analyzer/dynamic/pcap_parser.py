import os
from collections import Counter

class PCAPParser:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.results = {
            'dns_queries': [],
            'http_requests': [],
            'unique_ips': [],
            'summary': {}
        }

    def parse(self) -> dict:
        if not os.path.exists(self.pcap_path):
            return {"error": "PCAP file not found"}

        try:
            from scapy.all import rdpcap, DNSQR, IP, TCP, Raw
        except ImportError:
            return {"error": "scapy is not installed. Run: pip install scapy"}

        try:
            packets = rdpcap(self.pcap_path)
            
            ips = set()
            dns_queries = set()
            http_reqs = []

            for pkt in packets:
                # IP extraction
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    ips.add(src)
                    ips.add(dst)
                
                # DNS extraction
                if pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    if qname:
                        qname_str = qname.decode('utf-8', errors='ignore').rstrip('.')
                        dns_queries.add(qname_str)
                
                # HTTP extraction (naive)
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith('GET ') or payload.startswith('POST '):
                        lines = payload.split('\r\n')
                        req_line = lines[0]
                        host = "Unknown"
                        for line in lines:
                            if line.lower().startswith("host: "):
                                host = line.split(" ")[1].strip()
                                break
                        http_reqs.append({
                            "request": req_line,
                            "host": host
                        })

            # Filter out common local/multicast IPs to reduce noise
            filtered_ips = [ip for ip in ips if not ip.startswith('10.') and not ip.startswith('127.') and not ip.startswith('192.168.') and ip != '255.255.255.255']

            self.results['unique_ips'] = list(filtered_ips)
            self.results['dns_queries'] = list(dns_queries)
            self.results['http_requests'] = http_reqs
            self.results['summary'] = {
                'total_packets': len(packets),
                'unique_ips_count': len(filtered_ips),
                'dns_query_count': len(dns_queries),
                'http_request_count': len(http_reqs)
            }
            
            return self.results

        except Exception as e:
            return {"error": f"Failed to parse PCAP: {str(e)}"}
