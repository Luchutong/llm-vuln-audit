#!/usr/bin/env python3
"""Forward WSL eth0 ports to loopback container ports for Windows access."""
import socket
import threading

# listen host/port -> target 127.0.0.1 port
MAP = [
    ("0.0.0.0", 28880, 18880),  # Lab30
    ("0.0.0.0", 28090, 18090),  # phpMyFAQ
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


def handle(client, target_port):
    try:
        upstream = socket.create_connection(("127.0.0.1", target_port), timeout=10)
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
    for host, lport, tport in MAP:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, lport))
        s.listen(128)
        servers.append((s, tport))
        print("listening %s:%d -> 127.0.0.1:%d" % (host, lport, tport), flush=True)
    while True:
        for s, tport in servers:
            s.settimeout(1.0)
            try:
                client, _ = s.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(client, tport), daemon=True).start()


if __name__ == "__main__":
    main()
