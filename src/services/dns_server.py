import socketserver
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A

# IP of the public DNS server of Google
# The server has limited knowledge so it forwards to a recursive solver
FORWARDER_IP = "8.8.8.8"

# Local DNS records
DNS_RECORDS = {
    "fbi.confidential.": "10.0.0.50" # Attacker VM IP
}



class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, client_socket = self.request
        # raw data is in self.request[0]
        # socket is in self.request[1]

        try:
            # we parse the incoming DNS request
            request = DNSRecord.parse(data)
            question = request.q

            print(f"Received DNS request for {question.qname}")
            
            if question.qname in DNS_RECORDS:
                print(f"Found in the local records: {DNS_RECORDS[question.qname]}")
                
                # we create the reply
                reply = request.reply() # this already has the the header and question
                ip = DNS_RECORDS[question.qname]
                reply.add_answer(RR(question.qname, rdata=A(ip), ttl=60))

                #send
                client_socket.sendto(reply.pack(), self.client_address)
            else:
                print(f"Not in the records, we forward to {FORWARDER_IP}")

                # we will forward using the forwarder in dnslib
                proxy_request = DNSRecord.parse(data)
                response = proxy_request.send(FORWARDER_IP, 53, "udp")

                #send the response back to the client
                client_socket.sendto(response, self.client_address) 

        except Exception as e:
            print(f"Error parsing DNS request: {e}")


if __name__ == "__main__":
    server_address = ('',53)
    print(f"DNS Server running on {server_address[0]}:{server_address[1]}")
    print("Local records:")
    for domain, ip in DNS_RECORDS.items():
        print(f"{domain} -> {ip}")
    try:
        # create a server instance
        server = socketserver.UDPServer(server_address, DNSHandler)

        # start the server
        server.serve_forever()
    
    except PermissionError:
        print("Permission denied.")
    except Exception as e:
        print(f"Error starting DNS server: {e}")

