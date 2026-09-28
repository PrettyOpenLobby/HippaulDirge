#!/usr/bin/env python3
"""The client socket every doc_*_e2e.py script drives docudp.py with.

On Windows a UDP socket that sent a datagram to a port nothing listens on
gets the ICMP port-unreachable back as an error on its NEXT receive:
recv()/recvfrom() raise ConnectionResetError (WinError 10054) even though
nothing was lost that the caller could have read. Linux never reports it on
an unconnected socket. The scripts start and stop a server on a fixed
loopback port, twice or more per script, so a datagram that arrives while no
server is bound (before the next one has started, or after the last one
stopped) turned into a crash inside the scripts' drain() on Windows only.

Winsock switches the report off with the SIO_UDP_CONNRESET ioctl, but
Python's socket.ioctl() refuses that control code, so the socket below skips
the error instead: a receive that meets it simply carries on waiting, as it
would on Linux.

    from doc_e2e_udp import udp_socket
    sock = udp_socket()          # in place of socket.socket(AF_INET, SOCK_DGRAM)
"""
import socket


class E2ESocket(socket.socket):
    """A UDP socket whose receives skip Windows' ICMP port-unreachable reports."""

    def recv(self, *args):
        while True:
            try:
                return super().recv(*args)
            except ConnectionResetError:
                continue

    def recvfrom(self, *args):
        while True:
            try:
                return super().recvfrom(*args)
            except ConnectionResetError:
                continue


def udp_socket():
    """A fresh IPv4 UDP socket for a loopback test client."""
    return E2ESocket(socket.AF_INET, socket.SOCK_DGRAM)


def selftest():
    """Send to a port with no listener, then receive: a timeout, never a reset."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    dead = probe.getsockname()[1]
    probe.close()                        # nothing listens on `dead` now
    s = udp_socket()
    s.bind(("127.0.0.1", 0))
    s.settimeout(0.3)
    s.sendto(b"x", ("127.0.0.1", dead))
    try:
        s.recv(64)
        ok = False
    except socket.timeout:
        ok = True
    finally:
        s.close()
    print("doc_e2e_udp: a send to a closed port %s" % (
        "leaves the next receive to time out" if ok else "was answered?"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
