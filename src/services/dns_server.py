# src/services/simple_dns_server.py
import socket

def start_dns_server():
    """Start a simple DNS server for fbi.confidential."""
    host = "0.0.0.0"  # Listen on all interfaces
    port = 53  # Standard DNS port
    
    # Fake IP for fbi.confidential
    fake_ip = "10.0.0.99"

    # Create the server socket (UDP)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))  # Bind to all interfaces, DNS port
        print(f"DNS Server running on {host}:{port}")
        
        while True:
            data, client_address = server_socket.recvfrom(512)  # DNS packet size
            domain = extract_domain(data)
            if domain == "fbi.confidential":
                print(f"Request for {domain} from {client_address}, sending fake IP.")
                response = create_dns_response(data, fake_ip)
                server_socket.sendto(response, client_address)
            else:
                print(f"Request for {domain} from {client_address}, no response.")
                # No response or handle as needed for non-targeted queries

def extract_domain(data):
    """Extract the queried domain from the DNS request packet."""
    # Simplified extraction
    domain = data[12:].decode("utf-8").split("\x00")[0]  # This assumes a simple query
    return domain

def create_dns_response(request, fake_ip):
    """Create a DNS response packet with the fake IP."""
    # Simplified DNS response creation
    response = request[:2]  # Transaction ID remains unchanged
    response += b'\x81\x80'  # Response flags: standard query response
    response += b'\x00\x01'  # One question
    response += b'\x00\x01'  # One answer
    response += b'\x00\x00'  # No authority
    response += b'\x00\x00'  # No additional
    
    # Query Section (Question)
    response += request[12:]  # Copy the query section (Domain name)
    
    # Answer Section (fake IP for fbi.confidential)
    response += b'\xc0\x0c'  # Pointer to the domain name in the query section
    response += b'\x00\x01'  # Type A (host address)
    response += b'\x00\x01'  # Class IN (Internet)
    response += b'\x00\x00\x00\x3c'  # TTL = 60 seconds
    response += b'\x00\x04'  # Data length
    response += socket.inet_aton(fake_ip)  # The fake IP address for fbi.confidential
    
    return response

if __name__ == "__main__":
    start_dns_server()
