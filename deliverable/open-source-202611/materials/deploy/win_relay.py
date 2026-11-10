#!/usr/bin/env python3
"""User-mode relay: Windows 127.0.0.1 ports -> WSL eth0 relay -> containers."""
import socket
import threading

WSL_IP = "172.26.157.105"
# local 127.0.0.1 port -> WSL relay port
MAP = [
    ("127.0.0.1", 18880, 28880),  # Lab30
    ("127.0.0.1", 18090, 28090),  # phpMyFAQ
]


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, rport):
    try:
        upstream = socket.create_connection((WSL_IP, rport), timeout=10)
    except OSError:
        client.close()
        return
    t1 = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()


def main():
    servers = []
    for host, lport, rport in MAP:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, lport))
        s.listen(128)
        servers.append((s, rport))
        print("listening %s:%d -> %s:%d" % (host, lport, WSL_IP, rport), flush=True)
    while True:
        for s, rport in servers:
            s.settimeout(1.0)
            try:
                client, _ = s.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(client, rport), daemon=True).start()


if __name__ == "__main__":
    main()
