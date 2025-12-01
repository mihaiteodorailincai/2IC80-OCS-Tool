# src/services/https_server.py
import http.server
import ssl

def run_https_server():
    """Run the HTTPS server for fbi.confidential."""
    handler = http.server.SimpleHTTPRequestHandler
    server = http.server.HTTPServer(('0.0.0.0', 443), handler)
    
    # Wrap the server with SSL
    server.socket = ssl.wrap_socket(server.socket, keyfile="fbi.key", certfile="fbi.crt", server_side=True)
    print("HTTPS server running on https://fbi.confidential")
    server.serve_forever()

if __name__ == "__main__":
    run_https_server()
