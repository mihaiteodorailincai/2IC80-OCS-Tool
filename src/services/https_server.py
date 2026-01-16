# src/services/https_server.py
from http.server import HTTPServer
import ssl

from src.services.http_insecure_site import InsecureWebApp

def run():
    server = HTTPServer(("0.0.0.0", 443), InsecureWebApp)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="fbi.crt", keyfile="fbi.key")

    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print("HTTPS FBI Confidential server running on port 443")
    server.serve_forever()

if __name__ == "__main__":
    run()
