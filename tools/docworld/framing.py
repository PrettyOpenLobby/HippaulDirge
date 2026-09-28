"""The datagram: header offsets, the client's checksum, packet decoding for the log, the generic reply and the reliable ACK."""
import datetime
import struct
from .deps import _KELCRYPT, doc_kelcrypt


PORT = 55040
HDR_LEN = 24          # 8-byte outer header + the 16-byte INNER header
BODY_OFF = 24         # confirmed twice: from the capture, and from packet+24 in the handler
CKSUM_OFF = 10        # u16 LE.  parser 0x0058a0b0 sets s3 = packet+8 and reads s3+2.
MODE_OFF = 1          # packet[1] selects the cipher; 0 is a NO-OP (0x00584364)


def cksum(buf):
    """The client's own checksum, transcribed from `0x0058a080`.

        u32 sum = 0;
        for (i = 0; i < len; i++) sum += buf[i];
        sum = (sum >> 16) + sum;
        return sum & 0xffff;

    The parser zeroes the field at packet+10 before computing, so we do too.
    """
    b = bytearray(buf)
    b[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    total = 0
    for x in b:
        total = (total + x) & 0xFFFFFFFF
    total = (total + (total >> 16)) & 0xFFFFFFFF
    return total & 0xFFFF


def now_ms():
    """The client stamps a u16 of milliseconds at +4; mirror the same clock."""
    return int(datetime.datetime.now().timestamp() * 1000) & 0xFFFFFFFF


def hexdump(b, indent="    "):
    out = []
    for o in range(0, len(b), 16):
        chunk = b[o:o + 16]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append("%s%04x  %-47s  %s" % (indent, o, chunk.hex(" "), txt))
    return "\n".join(out)


def describe(b):
    """Decode the fields we actually know, so the log is readable at a glance."""
    if len(b) < 8:
        return "  (too short to parse)"
    t0, t1 = b[0], b[1]
    ln = struct.unpack_from("<H", b, 2)[0]
    ts = struct.unpack_from("<I", b, 4)[0]
    s = "  hdr=%02x %02x  len=%d(actual %d)  ms=%d" % (t0, t1, ln, len(b), ts)
    if len(b) >= 10:
        s += "  type@8=%d flags@9=%02x" % (b[8], b[9])
    if len(b) >= BODY_OFF + 2:
        s += "  subtype(body[1])=%d" % b[BODY_OFF + 1]
    if len(b) >= CKSUM_OFF + 2:
        declared = struct.unpack_from("<H", b, CKSUM_OFF)[0]
        s += "  cksum@10=%04x (recomputed %04x)" % (declared, cksum(b))
    if len(b) >= 80:
        s += "  tail=%s" % b[76:80].hex()
    return s


def describe_inner(b):
    """Decrypt pkt[8..23] with the client's own cipher and show the real header.

    The inner header is the only enciphered part of the datagram, and it carries
    the reliable-messaging SEQ we need in order to ACK precisely (sec 4ae/4ai).
    header() self-checks -- the decrypted cksum must equal the folded byte-sum of
    the decrypted packet -- so None here means the mode/key did not apply.
    """
    if not _KELCRYPT or len(b) < 24:
        return None
    try:
        hd = doc_kelcrypt.header(bytes(b))
        if hd is None and b[1] == 4:
            # sec 4ed: the game-server channel's MODE 4 is the mode-2 cipher
            # instance (the 16 zero bytes) under another mode byte -- the
            # dispatcher leaves mode 4 untouched, but decrypting the header
            # as mode 2 authenticates: measured on the 09-11 keepalives and
            # the team-join request 31.
            # WARNING:KEY: 2026-09-22: through decrypt_any, so EVERY shipped key object
            # is tried and not just the blob's own. The blob is JP; a US client's
            # mode-4 instance has different key words, and against the JP object
            # alone its briefing-room traffic authenticates under no mode at all.
            # That was CER-48101: unreadable keepalive requests, never answered,
            # [chan+224] stale, the 40 s watchdog. See doc_kelcrypt._profiles.
            out, _build = doc_kelcrypt.decrypt_any(bytes(b), mode=2)
            if out is not None:
                h = out[8:24]
                ck = struct.unpack_from("<H", h, 2)[0]
                hd = {
                    "type": h[0], "flags": h[1], "cksum": ck,
                    "ack_seq": struct.unpack_from("<H", h, 4)[0],
                    "seq": struct.unpack_from("<H", h, 6)[0],
                    "u32_16": struct.unpack_from("<I", h, 8)[0],
                    "u32_20": struct.unpack_from("<I", h, 12)[0],
                    "is_data": bool(h[1] & 0x01),
                    "is_ack": bool(h[1] & 0x02),
                    "plain": out, "mode4": True,
                }
        return hd
    except Exception:
        return None


def build_reply(req, mode, subtype, crypto, body_len, mode_byte=0, do_cksum=True,
                ptype=128, flags=0, lobby_ip=None, lobby_port=55040):
    """Assemble a candidate server->client datagram.

    Deliberately built from the same field layout the client sends, because that
    is the only layout we have ever seen.  Whether the server is supposed to use
    it is exactly what the experiment is testing.
    """
    if mode == "none":
        return None
    if mode == "echo":
        return req

    body = bytearray(body_len)
    # body[1] is the subtype the handler dispatches on.
    if body_len >= 2:
        body[1] = subtype

    # --- THE LOBBY REDIRECT ------------------------------------------------
    # Subtype-4's handler (0x00585ec8) reads exactly three fields out of the
    # body and hands two of them to the sockaddr builder 0x0058a970:
    #
    #     v1 = lw  [body+4]     ; must be >= 0 or the handler bails with -3
    #     a1 = lw  [body+12]    ; -> IP
    #     a2 = lhu [body+10]    ; -> port
    #
    # So the body of this message is a REDIRECT: it tells the client where the
    # lobby server lives.  Sending zeros made DoC dial 0.0.0.0:0, which the
    # emulog shows verbatim -- "Creating New UDP Connection ... to 0" 26 ms
    # after our reply, then "Closed Dead".  That is why the connection reached
    # state 7 and stuck: state 7 waits on the lobby sub-connection that never
    # came up.
    #
    # The encoding below was derived by INVERTING 0x0058a970 against the live
    # connection object's own address field (ctx+0x10 = 01 00 then the port
    # little-endian then the four octets REVERSED: 01 00 00 d7 3c 02 00 c0 for
    # 192.0.2.60:55040) rather than by reasoning about byte order, and it
    # reproduces the live deployment's eight bytes exactly.
    if body_len >= 16 and lobby_ip:
        o = [int(x) for x in lobby_ip.split(".")]
        ip_field = (o[3] << 24) | (o[2] << 16) | (o[1] << 8) | o[0]
        port_field = ((lobby_port >> 8) | (lobby_port << 8)) & 0xFFFF
        struct.pack_into("<H", body, 10, port_field)
        struct.pack_into("<I", body, 12, ip_field)
        # body+4 must be >= 0; 0 already satisfies it, left explicit for clarity.
        struct.pack_into("<i", body, 4, 0)

    if crypto == "echo" and len(req) >= HDR_LEN:
        mid = bytearray(req[8:24])      # give back the client's own 16 bytes
    elif crypto == "zero":
        mid = bytearray(16)
    else:                                # "copyhdr": echo, falling back to zeros
        mid = bytearray(req[8:24] if len(req) >= HDR_LEN else bytes(16))

    # The INNER HEADER, decoded from the parser at 0x0058a218:
    #   +0 (packet+8)  message type, dispatched at 0x0058a250ff
    #   +1 (packet+9)  flags; bit 3 (0x08) = "carries an ID at packet+16"
    #   +2 (packet+10) checksum, written later
    # Type dispatch, transcribed:  0 -> s6=12 | 1 -> s6=8 | 2 -> fallthrough
    #   3 -> s6=40 | 4 -> fallthrough | 126 -> s6=12 | 127,128 -> fallthrough
    #   254, 255 -> their own arms | anything else -> the generic arm
    # 128 (0x80) is the type the CLIENT itself sends, per its send record.
    mid[0] = ptype & 0xFF
    mid[1] = flags & 0xFF               # keep bit 3 clear => no ID lookup

    total = HDR_LEN + len(body)
    pkt = bytearray()
    pkt += bytes([0x04, mode_byte & 0xFF])
    pkt += struct.pack("<H", total)
    pkt += struct.pack("<I", now_ms() & 0xFFFF)
    pkt += mid
    pkt += body
    # The checksum must be written LAST, over the finished packet, with its own
    # field zeroed -- exactly what the parser does before comparing.
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    if do_cksum:
        pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)


def build_reliable_ack(ack_seq):
    """A header-only MODE-0 ACK for the reliable-messaging framework.

    PROVEN OFFLINE (an offline run of the client's own code (doc_ack_proof), against the client's own code): the framework
    header handler 0x005810d0 dispatches on record[1] (flags); bit1 (0x02) = ACK,
    which walks the pending-send list (framework+0x248) and, for the node whose
    message seq (sub[+0x0a]) == the received ack-seq, UNLINKS it (count 1->0) and
    fires the send-completion -- stopping the retransmit.  A 24-byte mode-0 packet
    with pkt[9]=0x02 (flags) and pkt[12..13]=ack-seq, run through kel's real
    parser + handler against the live framework, cancels the pending seq-28 send.

    The reliable channel honours mode 0 (no cipher), same as the lobby channel.
    type (pkt[8]) is NOT checked; use 0xFF to match the client's own ACK template.
    """
    pkt = bytearray(HDR_LEN)                    # header-only, no body (msg[18]=0)
    pkt[0] = 0x04
    pkt[1] = 0x00                                # mode 0
    struct.pack_into("<H", pkt, 2, HDR_LEN)
    struct.pack_into("<I", pkt, 4, now_ms() & 0xFFFF)
    pkt[8] = 0xFF                                # inner type (0xFF = the ACK template's type)
    pkt[9] = 0x02                                # inner flags -> record[1] bit1 = ACK
    struct.pack_into("<H", pkt, 12, ack_seq & 0xFFFF)   # ack-seq, read at pkt+12 by 0x005810d0
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = bytes(2)
    pkt[CKSUM_OFF:CKSUM_OFF + 2] = struct.pack("<H", cksum(pkt))
    return bytes(pkt)
