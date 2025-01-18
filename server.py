import argparse
import socket
import ssl
import threading
import sys
import os

def handle_tls_client(conn, aes_key_32):
    """
    Upon a new TLS client connection, send the 32-byte key, then close.
    """
    try:
        print("[TLS] Sending 32-byte key to client.")
        conn.sendall(aes_key_32)
    finally:
        conn.close()

def tls_server(tls_port, aes_key_32, certfile, keyfile):
    """
    Listens on the specified TLS port. On each new connection, we send the 32-byte key then close.
    """
    # Create TLS context (server side)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Load your self-signed cert and key
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', tls_port))   # Listen on all interfaces, user-specified port
    sock.listen(5)
    print(f"[TLS] Server started on port {tls_port}. Waiting for connections...")

    # Wrap the socket with TLS
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            print(f"[TLS] Accepted connection from {addr}")
            threading.Thread(target=handle_tls_client, args=(conn, aes_key_32)).start()

def handle_upload(conn, addr, outfile):
    """
    For each connected client on the raw TCP port, read data (encrypted file)
    and append it to a local file. Then close.
    """
    print(f"[TCP] Handling new upload connection from {addr}.")
    # Open (or create) an output file, in append-binary mode:
    with open(outfile, "ab") as f:
        while True:
            data = conn.recv(4096)
            if not data:
                # Client closed connection or error
                break
            f.write(data)
    conn.close()
    print(f"[TCP] Finished receiving data from {addr}.")

def tcp_server(tcp_port, outfile):
    """
    Listens on the specified TCP port (raw TCP, no TLS). The C code writes the encrypted data
    directly to this socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', tcp_port))
    sock.listen(5)
    print(f"[TCP] Server started on port {tcp_port}. Waiting for file uploads...")

    while True:
        conn, addr = sock.accept()
        print(f"[TCP] Accepted connection from {addr}")
        threading.Thread(target=handle_upload, args=(conn, addr, outfile)).start()

def main():
    parser = argparse.ArgumentParser(
        description="Run two servers: one TLS server that sends a 32-byte key, and one TCP server to receive file uploads."
    )
    parser.add_argument(
        "--tls-port",
        type=int,
        default=9999,
        help="Port for the TLS server (default: 9999)."
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=8080,
        help="Port for the raw TCP server (default: 8080)."
    )
    parser.add_argument(
        "--key",
        type=str,
        default="ThisIsA32ByteKeyForExample012345",
        help="A 32-byte key to send to TLS clients (default: 32-byte example key)."
    )
    parser.add_argument(
        "--cert",
        type=str,
        default="cert.crt",
        help="Path to the certificate file for TLS (default: cert.crt)."
    )
    parser.add_argument(
        "--cert-key",
        type=str,
        default="cert.key",
        help="Path to the private key file for TLS (default: cert.key)."
    )
    parser.add_argument(
        "--out-file",
        type=str,
        default="uploaded_file.bin",
        help="Path to the file where uploaded data will be appended (default: uploaded_file.bin)."
    )
    
    args = parser.parse_args()

    # Validate that the key is exactly 32 bytes
    aes_key_32 = args.key.encode('utf-8')
    if len(aes_key_32) != 32:
        print(f"Error: The provided key must be exactly 32 bytes. Current length: {len(aes_key_32)}")
        sys.exit(1)

    # Check if cert and key files exist (optional but helpful)
    if not os.path.exists(args.cert):
        print(f"Error: Certificate file {args.cert} does not exist.")
        sys.exit(1)
    if not os.path.exists(args.cert_key):
        print(f"Error: Certificate key file {args.cert_key} does not exist.")
        sys.exit(1)

    # Start both servers in separate daemon threads
    t1 = threading.Thread(
        target=tls_server,
        args=(args.tls_port, aes_key_32, args.cert, args.cert_key),
        daemon=True
    )
    t2 = threading.Thread(
        target=tcp_server,
        args=(args.tcp_port, args.out_file),
        daemon=True
    )

    t1.start()
    t2.start()

    print("[*] Both servers are running. Press Ctrl+C to stop.")
    
    # Keep the main thread alive
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[*] Shutting down servers...")

if __name__ == "__main__":
    main()
