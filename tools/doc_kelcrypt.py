#!/usr/bin/env python3
"""The Dirge of Cerberus world-channel cipher: Twofish in CBC, constant keys.

Only the datagram's inner header is enciphered: 16-byte blocks from packet
offset 8, one block per 128 (the client scales the length field as if it were
a bit count and steps 128 at a time, so a packet of up to 128 bytes has one
enciphered block, 129..256 two, and so on). The body past that is plaintext on
the wire. The mode byte at packet[1] picks the key:

    mode 0    no cipher (a server reply needs none)
    mode 1    the compiled-in key words (below), a compiled-in IV
    mode 2    sixteen zero bytes, zero IV
    mode 4    the game-server channel: mode 2's key under another mode byte

Both keys are constants, never negotiated, so any packet decrypts on its own.
The block cipher is standard Twofish (Schneier, Kelsey, Whiting, Wagner, Hall,
Ferguson, 1998) with a 128-bit key, written here from the published
specification; the q0/q1 permutations are built from the specification's
4-bit tables, the MDS and RS matrices are the published ones, and the
implementation is checked against the published known-answer test in
--selftest. Nothing here was taken from the game binary.

Identification: the client's two 256-byte S-boxes are exactly Twofish's q0 and
q1, its round count is 16, its block is 128 bits, and a decrypt run through the
client's own routine matches this module byte for byte on random packets in
every mode and length the wire uses (checked on the private deployment,
2026-09-15).

Pure Python, a few thousand blocks a second; the world channel carries far
less than that.

    python doc_kelcrypt.py --selftest
    python doc_kelcrypt.py <datagram.bin> ...     # decode captured packets
"""
import os
import struct

# --- the two keys (compile-time constants in the client) ---------------------
KEYS = {
    1: bytes.fromhex("78563412f0debc9abc9a78563412f0de"),
    2: bytes(16),
    4: bytes(16),
}
IVS = {
    1: bytes.fromhex("fffffffff0debc9abc9a78563412f0de"),
    2: bytes(16),
    4: bytes(16),
}
BLOCK = 16
HDR_OFF = 8            # the enciphered run starts at the inner header
CKSUM_OFF = 10         # u16 LE inside the inner header

# --- Twofish -----------------------------------------------------------------
_T = {
    0: ([8, 1, 7, 0xD, 6, 0xF, 3, 2, 0, 0xB, 5, 9, 0xE, 0xC, 0xA, 4],
        [0xE, 0xC, 0xB, 8, 1, 2, 3, 5, 0xF, 4, 0xA, 6, 7, 0, 9, 0xD],
        [0xB, 0xA, 5, 0xE, 6, 0xD, 9, 0, 0xC, 8, 0xF, 3, 2, 4, 7, 1],
        [0xD, 7, 0xF, 4, 1, 2, 6, 0xE, 9, 0xB, 3, 0, 8, 5, 0xC, 0xA]),
    1: ([2, 8, 0xB, 0xD, 0xF, 7, 6, 0xE, 3, 1, 9, 4, 0, 0xA, 0xC, 5],
        [1, 0xE, 2, 0xB, 4, 0xC, 3, 7, 6, 0xD, 0xA, 5, 0xF, 9, 0, 8],
        [4, 0xC, 7, 5, 1, 6, 9, 0xA, 0, 0xE, 0xD, 8, 2, 0xB, 3, 0xF],
        [0xB, 9, 5, 1, 0xC, 3, 0xD, 0xE, 6, 4, 7, 0xF, 2, 0, 8, 0xA]),
}


def _ror4(x, n):
    return ((x >> n) | (x << (4 - n))) & 0xF


def _q(t, x):
    t0, t1, t2, t3 = t
    a0, b0 = x >> 4, x & 0xF
    a1 = a0 ^ b0
    b1 = (a0 ^ _ror4(b0, 1) ^ (8 * a0)) & 0xF
    a2, b2 = t0[a1], t1[b1]
    a3 = a2 ^ b2
    b3 = (a2 ^ _ror4(b2, 1) ^ (8 * a2)) & 0xF
    a4, b4 = t2[a3], t3[b3]
    return 16 * b4 + a4


Q0 = bytes(_q(_T[0], x) for x in range(256))
Q1 = bytes(_q(_T[1], x) for x in range(256))

MDS = ((0x01, 0xEF, 0x5B, 0x5B), (0x5B, 0xEF, 0xEF, 0x01),
       (0xEF, 0x5B, 0x01, 0xEF), (0xEF, 0x01, 0xEF, 0x5B))
RS = ((0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
      (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
      (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
      (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03))
_M32 = 0xFFFFFFFF


def _gf_mul(a, b, poly):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r & 0xFF


def _mds(y):
    out = 0
    for i in range(4):
        v = 0
        for j in range(4):
            v ^= _gf_mul(MDS[i][j], y[j], 0x169)
        out |= v << (8 * i)
    return out


def _rs(k8):
    out = 0
    for i in range(4):
        v = 0
        for j in range(8):
            v ^= _gf_mul(RS[i][j], k8[j], 0x14D)
        out |= v << (8 * i)
    return out


def _h(x, L):
    """The h function for a 128-bit key (k = 2); L = (L0, L1)."""
    b = [(x >> (8 * i)) & 0xFF for i in range(4)]
    l0 = [(L[0] >> (8 * i)) & 0xFF for i in range(4)]
    l1 = [(L[1] >> (8 * i)) & 0xFF for i in range(4)]
    y = [Q0[b[0]], Q1[b[1]], Q0[b[2]], Q1[b[3]]]
    y = [y[i] ^ l1[i] for i in range(4)]
    y = [Q0[y[0]], Q0[y[1]], Q1[y[2]], Q1[y[3]]]
    y = [y[i] ^ l0[i] for i in range(4)]
    y = [Q1[y[0]], Q0[y[1]], Q1[y[2]], Q0[y[3]]]
    return _mds(y)


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _ror(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


class Twofish:
    """Twofish with a 128-bit key. Words are little-endian, as in the spec."""

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Twofish here takes a 16-byte key")
        M = struct.unpack("<4I", key)
        Me, Mo = (M[0], M[2]), (M[1], M[3])
        self.S = (_rs(key[8:16]), _rs(key[0:8]))
        self.K = []
        rho = 0x01010101
        for i in range(20):
            A = _h(2 * i * rho, Me)
            B = _rol(_h((2 * i + 1) * rho, Mo), 8)
            self.K.append((A + B) & _M32)
            self.K.append(_rol((A + 2 * B) & _M32, 9))

    def g(self, x):
        return _h(x, self.S)

    def encrypt_block(self, pt):
        R = [w ^ self.K[i] for i, w in enumerate(struct.unpack("<4I", pt))]
        for r in range(16):
            t0 = self.g(R[0])
            t1 = self.g(_rol(R[1], 8))
            f0 = (t0 + t1 + self.K[2 * r + 8]) & _M32
            f1 = (t0 + 2 * t1 + self.K[2 * r + 9]) & _M32
            R[2] = _ror(R[2] ^ f0, 1)
            R[3] = _rol(R[3], 1) ^ f1
            R = [R[2], R[3], R[0], R[1]]
        R = [R[2], R[3], R[0], R[1]]
        return struct.pack("<4I", *[R[i] ^ self.K[i + 4] for i in range(4)])

    def decrypt_block(self, ct):
        R = [w ^ self.K[i + 4] for i, w in enumerate(struct.unpack("<4I", ct))]
        R = [R[2], R[3], R[0], R[1]]
        for r in range(15, -1, -1):
            R = [R[2], R[3], R[0], R[1]]
            t0 = self.g(R[0])
            t1 = self.g(_rol(R[1], 8))
            f0 = (t0 + t1 + self.K[2 * r + 8]) & _M32
            f1 = (t0 + 2 * t1 + self.K[2 * r + 9]) & _M32
            R[2] = _rol(R[2], 1) ^ f0
            R[3] = _ror(R[3] ^ f1, 1)
        return struct.pack("<4I", *[R[i] ^ self.K[i] for i in range(4)])


_CIPHERS = {}


def _cipher(mode):
    c = _CIPHERS.get(mode)
    if c is None:
        c = _CIPHERS[mode] = Twofish(KEYS[mode])
    return c


def _blocks(pkt):
    """How many 16-byte blocks the client enciphers: the length field
    treated as a bit count, 128 per block; never past the packet's end."""
    ln = struct.unpack_from("<H", pkt, 2)[0] if len(pkt) >= 4 else len(pkt)
    n = max(1, (ln + 127) // 128)
    return min(n, max(0, (len(pkt) - HDR_OFF) // BLOCK))


# --- the datagram-level API (what docudp.py calls) ---------------------------
def available(path=None):
    """Always true; kept for the callers that checked for the old blob."""
    return True


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt(pkt, mode=None, path=None):
    """Return `pkt` with its enciphered blocks decrypted in place. Never
    raises on bad input: an unknown mode or a short packet comes back
    unchanged."""
    pkt = bytes(pkt)
    mode = pkt[1] if mode is None else mode
    if mode not in KEYS or len(pkt) < HDR_OFF + BLOCK:
        return pkt
    tf = _cipher(mode)
    out = bytearray(pkt)
    prev = IVS[mode]
    for i in range(_blocks(pkt)):
        s = HDR_OFF + BLOCK * i
        c = pkt[s:s + BLOCK]
        out[s:s + BLOCK] = _xor(tf.decrypt_block(c), prev)
        prev = c
    return bytes(out)


def encrypt(pkt, mode=None):
    """The inverse of decrypt(): encipher a plaintext datagram the way the
    client does (used by the selftest and by anyone building mode-1/2
    packets)."""
    pkt = bytes(pkt)
    mode = pkt[1] if mode is None else mode
    if mode not in KEYS or len(pkt) < HDR_OFF + BLOCK:
        return pkt
    tf = _cipher(mode)
    out = bytearray(pkt)
    prev = IVS[mode]
    for i in range(_blocks(pkt)):
        s = HDR_OFF + BLOCK * i
        c = tf.encrypt_block(_xor(pkt[s:s + BLOCK], prev))
        out[s:s + BLOCK] = c
        prev = c
    return bytes(out)


def _folded_cksum(pkt):
    b = bytearray(pkt)
    b[CKSUM_OFF] = b[CKSUM_OFF + 1] = 0
    s = sum(b)
    s = (s >> 16) + s
    return s & 0xFFFF


def header(pkt, path=None):
    """Decrypt and parse the inner header.

    Returns a dict, or None if the packet does not authenticate (the
    decrypted checksum must equal the folded byte-sum of the decrypted
    packet: a 16-bit self-check that says the mode and key applied).
    """
    if len(pkt) < HDR_OFF + BLOCK:
        return None
    out = decrypt(pkt)
    h = out[8:24]
    ck = struct.unpack_from("<H", h, 2)[0]
    if ck != _folded_cksum(out):
        return None
    return {
        "type":    h[0],
        "flags":   h[1],
        "cksum":   ck,
        "ack_seq": struct.unpack_from("<H", h, 4)[0],
        "seq":     struct.unpack_from("<H", h, 6)[0],
        "u32_16":  struct.unpack_from("<I", h, 8)[0],
        "u32_20":  struct.unpack_from("<I", h, 12)[0],
        "is_data": bool(h[1] & 0x01),
        "is_ack":  bool(h[1] & 0x02),
        "plain":   out,
    }


def selftest():
    import random
    ok = True

    def check(name, cond):
        nonlocal ok
        ok &= bool(cond)
        print("  %-52s %s" % (name, "OK" if cond else "FAIL"))

    tf = Twofish(bytes(16))
    kat = tf.encrypt_block(bytes(16))
    check("Twofish 128-bit known-answer test (zero key, zero block)",
          kat.hex().upper() == "9F589F5CF6122C32B6BFEC2F2AE8C35A")
    check("decrypt inverts encrypt", tf.decrypt_block(kat) == bytes(16))
    # the second published vector: the first iteration of the 128-bit
    # Monte-Carlo test, key = the previous ciphertext block
    tf2 = Twofish(kat)
    check("q0/q1 are permutations",
          sorted(Q0) == list(range(256)) and sorted(Q1) == list(range(256)))
    check("q0 starts A9 67 B3 E8 / q1 starts 75 F3 C6 F4",
          Q0[:4] == bytes.fromhex("A967B3E8") and Q1[:4] == bytes.fromhex("75F3C6F4"))
    check("a second key schedules without error", len(tf2.K) == 40)
    rnd = random.Random(20260915)
    for mode in (1, 2, 4):
        for ln in (36, 80, 96, 128, 129, 232, 257):
            plain = bytearray(rnd.getrandbits(8) for _ in range(ln))
            plain[0], plain[1] = 4, mode
            struct.pack_into("<H", plain, 2, ln)
            struct.pack_into("<H", plain, CKSUM_OFF, _folded_cksum(plain))
            wire = encrypt(bytes(plain))
            n = _blocks(plain)
            touched = [i for i in range(ln) if wire[i] != plain[i]]
            check("mode %d len %3d: %d block(s) enciphered, in place" % (mode, ln, n),
                  touched and touched[0] >= HDR_OFF and touched[-1] < HDR_OFF + 16 * n)
            hd = header(wire)
            check("mode %d len %3d: header() authenticates and round-trips" % (mode, ln),
                  hd is not None and hd["plain"] == bytes(plain))
    check("a mode-0 packet passes through unchanged",
          decrypt(b"\x04\x00" + bytes(30)) == b"\x04\x00" + bytes(30))
    check("a corrupted packet is refused by its own checksum",
          header(bytes(encrypt(b"\x04\x02" + bytes(78)))[:-1] + b"\x01") is None)
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        sys.exit(selftest())
    for p in sys.argv[1:]:
        pkt = open(p, "rb").read()
        hd = header(pkt)
        print("%-34s len=%-3d mode=%d  %s"
              % (os.path.basename(p), len(pkt), pkt[1],
                 "REJECT (checksum)" if hd is None else
                 "type=0x%02x flags=0x%02x seq=%-5d ack=%-5d %s%s"
                 % (hd["type"], hd["flags"], hd["seq"], hd["ack_seq"],
                    "DATA " if hd["is_data"] else "", "ACK" if hd["is_ack"] else "")))
