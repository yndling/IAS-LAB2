"""Minimal TLS 1.3 handshake demonstration using Python's ssl module.

This module provides simple functions to spin up a TLS server and client
that perform a 1.3 handshake using OpenSSL under the hood.  The intent is
purely educational; real applications should rely on full-featured
libraries and proper certificate management.

There is no packet capture here, but the comments describe how to use
`openssl s_client` / `s_server` and Wireshark to inspect the resulting
traffic if desired.
"""

import socket
import ssl
import threading


def start_tls_server(host: str = '127.0.0.1', port: int = 8443,
                     certfile: str = 'server.pem', keyfile: str = 'server.key'):
    """Launch a simple TLS 1.3 echo server in a background thread.

    A self-signed certificate can be generated with OpenSSL:

        openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key \
                -out server.pem -days 1 -subj '/CN=localhost'
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # force 1.2/1.3
    # Leave cipher selection to OpenSSL defaults; some Windows builds of
    # OpenSSL/Schannel may not support TLS 1.3 cipher strings via
    # set_ciphers(), causing a "No cipher can be selected" error.
    def handle_client(conn, addr):
        with conn:
            data = conn.recv(1024)
            conn.sendall(data)

    def run():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    client, addr = ssock.accept()
                    threading.Thread(target=handle_client, args=(client, addr)).start()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def tls_client(host: str = '127.0.0.1', port: int = 8443,
               cafile: str | None = None) -> bytes:
    """Connect to the TLS server and return the response.  ``cafile`` can
    contain the server certificate for verification (or ``None`` to skip)."""

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if cafile is None:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.load_verify_locations(cafile)

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(b'hello')
            return ssock.recv(1024)
