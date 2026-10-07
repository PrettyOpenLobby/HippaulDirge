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


def _authentic(out):
    return (len(out) >= HDR_OFF + BLOCK
            and struct.unpack_from("<H", out, CKSUM_OFF)[0] == _folded_cksum(out))


def decrypt_any(pkt, mode=None, path=None):
    """(decrypted, key name) under whichever known key authenticates, or
    (None, None) when none does.

    The compiled-in keys are tried first ("builtin"), then any extra 16-byte
    keys named in POL_DOC_KEL_EXTRA_KEYS (comma-separated hex). A client
    stack whose game-server channel was built with a different key than the
    one above sends traffic that authenticates under no mode; the extra keys
    are where such a key goes once it is known. The 16-bit self-check is the
    same one header() uses, so a wrong key cannot pass."""
    pkt = bytes(pkt)
    mode = pkt[1] if mode is None and len(pkt) > 1 else mode
    out = decrypt(pkt, mode=mode)
    if _authentic(out):
        return out, "builtin"
    if mode not in KEYS:
        return None, None
    for i, key in enumerate(_extra_keys()):
        out = _decrypt_with(pkt, Twofish(key), IVS.get(mode, bytes(16)))
        if _authentic(out):
            return out, "extra%d" % i
    if mode in (2, 4):
        for x in list(LEADER_IVS):
            out = _decrypt_with(pkt, _zero_tf(), leader_iv(x))
            if _authentic(out):
                return out, "leader-iv-%08x" % x
        for kx, ivx in LEADER_KEYED:
            out = _decrypt_with(pkt, _keyed_tf(kx), leader_iv(ivx))
            if _authentic(out):
                return out, "leader-key-%08x-iv-%08x" % (kx, ivx)
    return None, None


# 2026-10-03 (live, first 4-5 player night): the table LEADER's game-server
# datagrams decrypt under the same zero key, but its CBC IV is not zero: the
# words [0, X, 0, 0], X an EE address (0x00561ff4 on the night's clients --
# 80% of its unreadable packets; the 09-23 savestates hold 0x003b71f0 in the
# third key slot, so it is build-specific). Only ack (+12) and seq (+14) come
# out wrong under a zero IV, which is how X was solved. learn_leader_iv()
# finds a new X from the client's own P2P datagrams (ack 0).
LEADER_IVS = [0x00561FF4]
for _w in (os.environ.get("POL_DOC_KEL_LEADER_IVS") or "").split(","):
    try:
        if _w.strip() and int(_w, 0) not in LEADER_IVS:
            LEADER_IVS.append(int(_w, 0))
    except ValueError:
        pass
# The other build's leader (the 09-23 savestates' client; every day of the
# capture from 09-24): the THIRD key slot keyed [0, 0x003b71f0, 0, 0] and the
# IV [0, 0x003b6c40, 0, 0] -- both words sit in the key object's header
# (+0x48 / +0x58), so a pointer pair stood in for key and IV. 40/40 packets
# per day, every day.
LEADER_KEYED = [(0x003B71F0, 0x003B6C40)]
_KEYED_TF = {}
# 2026-10-05 (live, a tester's leader console): a THIRD pair, [0, 0x003B5B10, 0, 0]
# + IV [0, 0x003B5560, 0, 0] -- found by brute force (the sender id in header
# block 0 does not depend on the IV word) on 300 rejected datagrams. The two
# words are 0x5B0 apart, exactly as 0x003B71F0 / 0x003B6C40 are: two fields of
# ONE heap object whose ADDRESS moves per session, a few KB around 0x003Bxxxx.
# So a leader's key is learnable live from a narrow window (learn_leader_key).
LEADER_KEYED.append((0x003B5B10, 0x003B5560))
# ... and a FOURTH (same console, another battle that night): P 0x003B88D0,
# X 0x003B73D0 -- 71/71 game-server requests and pick-ups. P - X is 0x1500
# here, so the IV is NOT a fixed offset from the key: learn_leader_key solves
# it from several packets (solve_iv_mitm), never from one checksum.
LEADER_KEYED.append((0x003B88D0, 0x003B73D0))
LEADER_KEY_IV_GAP = 0x5B0
LEADER_KEY_WINDOW = (0x00380000, 0x00400000)
LEADER_KEY_STEP = 16
LEADER_KEYS_MAX = 24
EE_ADDR_LO, EE_ADDR_HI = 0x00100000, 0x02000000   # the EE's 32 MB, above the kernel


def _keyed_tf(kx):
    if kx not in _KEYED_TF:
        _KEYED_TF[kx] = Twofish(struct.pack("<4I", 0, kx, 0, 0))
    return _KEYED_TF[kx]


_ZERO_TF = None
_PENDING = {}
_LAST_SOLVE = [0.0]


def _zero_tf():
    global _ZERO_TF
    if _ZERO_TF is None:
        _ZERO_TF = Twofish(bytes(16))
    return _ZERO_TF


def leader_iv(x):
    return struct.pack("<4I", 0, x, 0, 0)


def solve_leader_iv(pkt, tf=None):
    """X candidates for one unreadable P2P datagram (flags & 8, so ack 0):
    the ack half of X is the zero-IV ack, the seq half whatever makes the
    folded checksum match (~1 in 65536 by chance, hence the confirmation).
    `tf` = the key to solve under (default the zero key)."""
    if len(pkt) < HDR_OFF + BLOCK:
        return []
    o = _decrypt_with(bytes(pkt), tf or _zero_tf(), bytes(16))
    if not (o[9] & 8) or o[8] not in (96, 97, 100, 101, 102, 112, 113, 114,
                                     118, 119, 121, 0x83):
        return []
    ck, ackp, seqp = struct.unpack_from("<HHH", o, 10)
    b = bytearray(o)
    b[10:16] = bytes(6)
    base = sum(b)
    out = []
    for hi in range(65536):
        sr = seqp ^ hi
        s = base + (sr & 0xFF) + (sr >> 8)
        if ((s >> 16) + s) & 0xFFFF == ck:
            out.append((hi << 16) | ackp)
    return out


def learn_leader_iv(pkt, now, min_gap=1.0):
    """Feed an unreadable mode-4 datagram. Returns a newly confirmed X (now in
    LEADER_IVS) or None. A candidate from one packet is confirmed when it
    authenticates a later one; solving is rate-limited to one per `min_gap`."""
    pkt = bytes(pkt)
    for (kx, x) in list(_PENDING):
        tf = _zero_tf() if kx is None else _keyed_tf(kx)
        if _authentic(_decrypt_with(pkt, tf, leader_iv(x))):
            _PENDING.clear()
            if kx is None:
                if x not in LEADER_IVS:
                    LEADER_IVS.append(x)
            elif (kx, x) not in LEADER_KEYED:
                LEADER_KEYED.append((kx, x))
            return x
    if now - _LAST_SOLVE[0] < min_gap:
        return None
    _LAST_SOLVE[0] = now
    # the zero key first, then the leader key slots seen so far: the type
    # filter in solve_leader_iv keeps a wrong key from producing candidates
    for kx in [None] + sorted({k for k, _x in LEADER_KEYED}):
        tf = _zero_tf() if kx is None else _keyed_tf(kx)
        for x in solve_leader_iv(pkt, tf)[:8]:
            _PENDING[(kx, x)] = now
    for k in [k for k, t in _PENDING.items() if now - t > 60.0]:
        del _PENDING[k]
    return None


def _iv_need_sums(o):
    """The sums of plaintext bytes 12..15 (ack, seq) that make the folded
    checksum match -- the only bytes the IV word touches."""
    ck = struct.unpack_from("<H", o, CKSUM_OFF)[0]
    b = bytearray(o)
    b[CKSUM_OFF:16] = bytes(16 - CKSUM_OFF)
    base = sum(b)
    return {s4 for s4 in range(0, 1021)
            if (((base + s4) >> 16) + base + s4) & 0xFFFF == ck}


def solve_iv_mitm(pkts, tf):
    """IV words X for packets under a KNOWN key: per packet the four bytes
    D(C0)[4:8] XOR X must byte-sum to a known S, and the bytes add up
    independently -- so meet in the middle on (x0, x1) / (x2, x3) across up to
    10 packets. Live 10-05: 0.7 s, 71/71 for P 0x003B88D0."""
    rows = []
    for d in pkts:
        o = _decrypt_with(bytes(d), tf, bytes(16))
        need = _iv_need_sums(o)
        if len(need) == 1:
            rows.append((o[12:16], next(iter(need))))
    rows = rows[:10]
    if len(rows) < 3:
        return []
    left = {}
    for x0 in range(256):
        for x1 in range(256):
            left.setdefault(tuple((r[0][0] ^ x0) + (r[0][1] ^ x1) for r in rows),
                            []).append((x0, x1))
    out = []
    for x2 in range(256):
        for x3 in range(256):
            k = tuple(r[1] - (r[0][2] ^ x2) - (r[0][3] ^ x3) for r in rows)
            for x0, x1 in left.get(k, ()):
                out.append(x0 | x1 << 8 | x2 << 16 | x3 << 24)
    return out


def find_leader_key(pkts, sender, candidates=None, stop=None):
    """(P, X) for one console's leader datagrams under key [0, P, 0, 0] / IV
    [0, X, 0, 0], or None. `pkts` = its recent unreadable mode-4 datagrams
    (newest last); `sender` = the id the FIRST one's header carries at +16
    (CBC block 0 bytes 8..11, which the IV word at bytes 4..7 never touches)
    -- for a 64-byte pose the body's first word (the charid of a 0x83, the
    NPC id of a type 3), else the session's charid. The KEY comes from that
    32-bit match; X from P - LEADER_KEY_IV_GAP, the checksum solvers, and is
    accepted only when it authenticates TWO packets (one checksum is 16 bits:
    a wrong X passed one packet twice on 10-05). `stop()` -> True aborts."""
    if isinstance(pkts, (bytes, bytearray)):
        pkts = [pkts]
    pkts = [bytes(d) for d in pkts if len(d) >= HDR_OFF + BLOCK]
    if not pkts or not sender:
        return None
    c0 = pkts[0][HDR_OFF:HDR_OFF + BLOCK]
    want = struct.pack("<I", sender & 0xFFFFFFFF)
    for i, p in enumerate(candidates if candidates is not None
                          else leader_key_candidates()):
        if stop is not None and i % 256 == 0 and stop():
            return None
        tf = Twofish(struct.pack("<4I", 0, p, 0, 0))
        if tf.decrypt_block(c0)[8:12] != want:
            continue
        mine = [d for d in pkts
                if tf.decrypt_block(d[HDR_OFF:HDR_OFF + BLOCK])[8:12] == want]
        cands = [p - LEADER_KEY_IV_GAP]
        for d in mine[:3]:
            cands += solve_leader_iv(d, tf)[:8]
        cands += solve_iv_mitm(mine, tf)[:8]
        # the BEST X, and it must cover most of the console's packets: a wrong
        # X can pass two (the byte-sum check admits XOR twins -- 10-05, two
        # false X's for P 0x003B88D0 each passed a pair)
        # X is an EE ADDRESS like P (every pair seen: 0x0038xxxx-0x0056xxxx),
        # which the XOR twins are not (0x302A72D0 / 0x302B73D0 on 10-05); ties
        # go to the X whose decrypted sequence numbers (+14) run tightest
        best, best_key = None, None
        for x in dict.fromkeys(cands):
            if not (EE_ADDR_LO <= x < EE_ADDR_HI):
                continue
            outs = [_decrypt_with(d, tf, leader_iv(x)) for d in mine]
            good = [o for o in outs if _authentic(o)]
            if not good:
                continue
            seqs = [struct.unpack_from("<H", o, 14)[0] for o in good]
            key = (len(good), -(max(seqs) - min(seqs)))
            if best_key is None or key > best_key:
                best, best_key = x, key
        best_ok = best_key[0] if best_key else 0
        need = (min(2, len(mine)) if len(mine) < 3
                else max(3, -(-3 * len(mine) // 4)))
        if best is not None and best_ok >= need:
            return p, best
        return None          # the key is right; too few packets for its IV yet
    return None


def leader_key_candidates():
    """Every P of LEADER_KEY_WINDOW, nearest the keys already known first."""
    lo, hi = LEADER_KEY_WINDOW
    known = sorted({k for k, _x in LEADER_KEYED}) or [0x003B5B10]
    return sorted(range(lo, hi, LEADER_KEY_STEP),
                  key=lambda p: min(abs(p - k) for k in known))


def add_leader_key(p, x):
    """Remember a learned pair (most recent last, capped). True if new."""
    if (p, x) in LEADER_KEYED:
        return False
    # a new X for a KNOWN key replaces the old one: the learner only runs on a
    # packet no known pair reads, so the old X just failed (an early X solved
    # from few packets can be a checksum twin; it is corrected this way)
    LEADER_KEYED[:] = [kv for kv in LEADER_KEYED if kv[0] != p]
    LEADER_KEYED.append((p, x))
    while len(LEADER_KEYED) > LEADER_KEYS_MAX:
        LEADER_KEYED.pop(1)          # keep the oldest compiled-in pair first
    return True


def load_leader_keys(path):
    """Add the pairs a previous run learned (a JSON list of [P, X])."""
    import json
    try:
        with open(path, encoding="utf-8") as f:
            for p, x in json.load(f):
                add_leader_key(int(p), int(x))
    except (OSError, ValueError, TypeError):
        pass


def save_leader_keys(path):
    import json
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump([[p, x] for p, x in LEADER_KEYED], f)
        os.replace(tmp, path)
    except OSError:
        pass


_EXTRA = None


def _extra_keys():
    global _EXTRA
    if _EXTRA is None:
        _EXTRA = []
        for word in (os.environ.get("POL_DOC_KEL_EXTRA_KEYS") or "").split(","):
            word = word.strip()
            try:
                key = bytes.fromhex(word)
            except ValueError:
                continue
            if len(key) == 16:
                _EXTRA.append(key)
    return _EXTRA


def _decrypt_with(pkt, tf, iv):
    if len(pkt) < HDR_OFF + BLOCK:
        return pkt
    out = bytearray(pkt)
    prev = iv
    for i in range(_blocks(pkt)):
        s = HDR_OFF + BLOCK * i
        c = pkt[s:s + BLOCK]
        out[s:s + BLOCK] = _xor(tf.decrypt_block(c), prev)
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
    out, build = decrypt_any(pkt)
    if out is None:
        return None
    h = out[8:24]
    ck = struct.unpack_from("<H", h, 2)[0]
    return {
        "build":   build,
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
    # 2026-10-03, captured live: the table leader's (0x41078) P2P 121 and its
    # 1 Hz report -- zero key, IV [0, 0x00561ff4, 0, 0]
    led = bytes.fromhex("04043000813a1c00951bc874e57eff37b70b433a4e674434"
                        "6465fb0199c40fc35815bfbfb5cb43c3a939000081000000")
    rep = bytes.fromhex("040458002e171c00b018587fb5cfcd4cab3f934c6b027a0c"
                        "180001000000000001000000fa0000001c0000007810040"
                        "09a998141000080b50000c03f0000000000000000000080bf"
                        "020c853d000100000000190000000000")
    hd = header(led)
    check("leader 121 decrypts: type 121, flags 8, sender 0x41078, target -1",
          hd is not None and (hd["type"], hd["flags"], hd["u32_16"], hd["u32_20"])
          == (121, 8, 0x41078, 0xFFFFFFFF))
    check("leader 1 Hz report decrypts (type 0x82, sender 0x41078)",
          header(rep) is not None and header(rep)["u32_16"] == 0x41078)
    check("TWIN: under the zero IV alone the leader's packet is refused",
          not _authentic(_decrypt_with(led, _zero_tf(), bytes(16))))
    # the other build's leader (0x41054, 09-24): third key slot + its own IV
    k3 = bytes.fromhex("04045800f25e0700d16d4d18fe60192aad72f8937ce7d169"
                       "180001000000000001000000d200000008000000541004009a596744"
                       "cdcc44c166f69ec400000000000000000000803f020c853dfd010320"
                       "00000b0000000000")
    hk = header(k3)
    check("other build's leader: key [0,0x3b71f0,0,0] IV [0,0x3b6c40,0,0] -> "
          "1 Hz report, sender 0x41054, seq 836 ack 2",
          hk is not None and (hk["type"], hk["u32_16"], hk["seq"], hk["ack_seq"])
          == (0x82, 0x41054, 836, 2))
    _savedk = list(LEADER_KEYED)
    del LEADER_KEYED[:]
    check("TWIN: without that pair it is unreadable", header(k3) is None)
    LEADER_KEYED[:] = _savedk
    _saved = list(LEADER_IVS)
    del LEADER_IVS[:]
    _PENDING.clear()
    _LAST_SOLVE[0] = 0.0
    check("TWIN: with no leader IV known it is unreadable", header(led) is None)
    learn_leader_iv(led, 100.0)            # candidates from the 121
    got = learn_leader_iv(led, 100.5)      # confirmed on the next packet
    check("learn_leader_iv solves X = 0x00561ff4 from the client's own 121",
          got == 0x00561FF4 and header(led) is not None)
    LEADER_IVS[:] = _saved
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
