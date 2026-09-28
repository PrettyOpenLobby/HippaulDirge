"""The address a client is handed, chosen per client (POL_ADVERTISE_PUBLIC / _LAN), and the table record stamped with it."""
import os
import socket
import ipaddress as _ipaddress
from . import tableverbs



# ---- the address a client is handed, chosen per client ---------------------
# --lobby-ip / --frag3-servers / the game-server endpoint were ONE address for
# every player. A deployment can have players on several networks (a LAN, a
# VPN, the internet through a forwarding front end) and each can reach only
# one of the server's addresses. The core applies the same rule; it is kept
# local here so this service needs nothing from the core's code:
#
#   0. POL_ADVERTISE_PUBLIC, when set, for a peer with a GLOBAL address (a
#      front end that forwards with the source intact).
#   1. POL_ADVERTISE_LAN, when set, for an RFC1918 peer.
#   2. otherwise, configured address off the LAN and peer RFC1918: the local
#      address the kernel would use to reach that peer.
#   3. otherwise the configured address, exactly as before.
_RFC1918_NETS = tuple(_ipaddress.ip_network(n) for n in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))  # generic RFC1918 example; polcheck: allow


def _ip_or_none(text):
    try:
        a = _ipaddress.ip_address(text)
    except (ValueError, TypeError):
        return None
    return getattr(a, "ipv4_mapped", None) or a


def _is_rfc1918(a):
    return a is not None and any(a in n for n in _RFC1918_NETS)


def host_for(default, peer_ip):
    """The host to write into a packet for the client at `peer_ip`. Never
    raises; an empty/None `default` stays empty (the caller's "no address")."""
    peer = _ip_or_none(peer_ip)
    if not default or peer is None or peer.is_loopback:
        return default
    public_ip = (os.environ.get("POL_ADVERTISE_PUBLIC") or "").strip()
    if public_ip and peer.is_global:
        return public_ip
    if _is_rfc1918(peer):
        lan_ip = (os.environ.get("POL_ADVERTISE_LAN") or "").strip()
        if lan_ip:
            return lan_ip
        if not _is_rfc1918(_ip_or_none(default)):
            try:
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    probe.connect((str(peer), 9))
                    src = probe.getsockname()[0]
                finally:
                    probe.close()
            except OSError:
                return default
            if _is_rfc1918(_ip_or_none(src)):
                return src
    return default


def rec_for(rec, default_gs_ip, peer_ip):
    """A battle-table record as THIS recipient must see it. The store stamps one
    game-server address into every record (BattletableStore._stamp); a table can
    seat a LAN console and an internet player together, so the address is
    rewritten per recipient on the way out. Returns `rec` untouched when there
    is nothing to change."""
    if rec is None or not default_gs_ip:
        return rec
    ip = host_for(default_gs_ip, peer_ip)
    if ip == default_gs_ip or len(rec) < tableverbs.BT_OFF_GS_IP + 4:
        return rec
    out = bytearray(rec)
    out[tableverbs.BT_OFF_GS_IP:tableverbs.BT_OFF_GS_IP + 4] = bytes(int(x) for x in ip.split("."))
    return type(rec)(out) if isinstance(rec, bytes) else out
