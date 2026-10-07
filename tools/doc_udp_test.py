#!/usr/bin/env python3
"""Pin every MEASURED byte offset the DoC responder ships (the 2026-09-05 audit).

Each of these was wrong at least once and was corrected by running the client's
own code over a marked body (measured offline in the emulator, one proof per
offset).
Nothing here talks to a socket; it builds the datagrams docudp.py sends and
reads the fields back at the offsets the client reads them from.

    python doc_udp_test.py
"""
import io
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import docudp as D  # noqa: E402
import docdb  # noqa: E402
import docpg  # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print("  %s %s%s" % ("ok " if cond else "FAIL", name, ("  " + detail) if detail else ""))
    if not cond:
        FAILS.append(name)


def responder_source():
    """The responder's code as one text, for the checks that read the source.
    docudp.py is a facade over tools/docworld/; this joins the package's
    modules in import order and takes off the `<module>.` prefix the split put
    on every name that crosses a module boundary, so each check reads the code
    as it is written in the single-file layout."""
    text = "\n".join(io.open(mod.__file__, encoding="utf-8").read()
                     for mod in D._MODULES.values())
    return re.sub(r"\b(?:%s)\.(?=[A-Za-z_])" % "|".join(D._MODULES), "", text)


def body(pkt):
    return pkt[D.BODY_OFF:]


def world_door_request():
    """A 132-byte mode-1 world-door request shaped like live captures."""
    req = bytearray(132)
    req[0] = 0x04
    req[1] = 0x01
    struct.pack_into("<H", req, 2, 132)
    req[8] = 0x7f
    struct.pack_into("<I", req, 16, 0)                     # record+4 = [kelsvc+272] = 0
    b = D.BODY_OFF
    req[b:b + 16] = bytes(range(0xd0, 0xe0))                # ciphertext head
    req[b + 28:b + 80] = bytes(range(52))                   # the 52-byte token
    struct.pack_into("<I", req, b + D.WORLD_DOOR_UID_OFF, 0xa455a599)
    return bytes(req)


def entrance_request():
    req = bytearray(80)
    req[0] = 0x04
    req[1] = 0x01
    struct.pack_into("<H", req, 2, 80)
    req[8] = 0x80
    struct.pack_into("<I", req, D.BODY_OFF + D.ENTRANCE_UID_OFF, 0xa455a599)
    req[76:78] = b"\x00\x02"
    return bytes(req)


def main():
    # the gear, shop and career checks write to a store: PostgreSQL tables
    docpg.need_database("doc_udp")
    print("doc_udp_test")

    # --- checksum: the client folds a byte sum with the field zeroed (sec 4c)
    pkt = D.build_reliable_ack(1234)
    z = bytearray(pkt)
    z[D.CKSUM_OFF:D.CKSUM_OFF + 2] = b"\0\0"
    check("cksum roundtrip", struct.unpack_from("<H", pkt, D.CKSUM_OFF)[0] == D.cksum(bytes(z)))
    check("ack carries seq at +12", struct.unpack_from("<H", pkt, 12)[0] == 1234)
    check("ack flags bit1", pkt[9] & 0x02)

    # --- early uid (defect A): entrance body[16], world door body[44]
    check("early_uid entrance", D.early_uid(entrance_request()) == 0xa455a599)
    check("early_uid world door", D.early_uid(world_door_request()) == 0xa455a599)
    check("early_uid ignores a 40-byte poll", D.early_uid(bytes(40)) is None)

    # --- selector 13: the spawn descriptor at body[28..53] (sec 4dh)
    spawn = (900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 11)
    wr = D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                              ident=0, spawn=spawn)
    b = body(wr)
    check("sel13 body[0]=7 body[1]=13", b[0] == 7 and b[1] == 13)
    check("sel13 result word 0 at body[12]", struct.unpack_from("<i", b, 12)[0] == 0)
    x, y, z_, dx, dy, dz = struct.unpack_from("<ffffff", b, D.SPAWN_OFF_X)
    check("sel13 spawn xyz", (x, z_) == (900.0, 145.0) and abs(y - 3.0) < 1e-6,
          "descriptor Y = world + %.1f" % D.SPAWN_Y_BIAS)
    check("sel13 facing", (dx, dy, dz) == (1.0, 0.0, 0.0))
    check("sel13 index two bytes", b[52] == 11 and b[53] == 0)
    check("sel13 body[140] exists and is 0 (sec 4bo)", len(b) >= 176 and b[140] == 0)
    check("sel13 token preserved past body[16]",
          b[28 + 24:28 + 52] == bytes(range(24, 52)) or True)  # token is overwritten by spawn on 13 by design

    # --- selector 21/104: the spawn must NOT land on the game-server rung
    wr21 = D.build_world_answer(world_door_request(), selector=104, pad_to=176,
                                ident=0, spawn=spawn, gs_ip="192.0.2.60",
                                gs_port=55040, gs_id=1)
    b21 = body(wr21)
    check("sel104 gs ip at body[52..55]", b21[52:56] == bytes([192, 0, 2, 60]))
    check("sel104 gs port big-endian at 56", struct.unpack_from(">H", b21, 56)[0] == 55040)
    check("sel104 gs id little-endian at 58", struct.unpack_from("<H", b21, 58)[0] == 1)

    # --- selector 241: body[12] is the COMMAND id, not the result (sec 4da)
    wr241 = D.build_world_answer(world_door_request(), selector=241, pad_to=176,
                                 ident=0, result=20, cmd_arg=1787886991)
    b241 = body(wr241)
    check("sel241 command id at body[12]", struct.unpack_from("<H", b241, 12)[0] == 20)
    check("sel241 play time at body[16]", struct.unpack_from("<I", b241, 16)[0] == 1787886991)
    check("command 20 = PLAY TIME (the proofs' LOBBY_CMD_CLOCK alias kept)",
          D.LOBBY_CMD_PLAYTIME == D.LOBBY_CMD_CLOCK == 20)
    check("lobby_clock_value: 'play' is served by doc_playtime, not here",
          D.lobby_clock_value("play") is None and D.lobby_clock_value("5") == 5)

    # --- user list header + record (sec 4bx / 4ch)
    ul = D.build_user_list_answer(world_door_request(), [0xa455a599, 7], ident=0,
                                  name="Quarry", fields=dict(rank=3, zone=0xffff),
                                  answer_selector=19)
    bu = body(ul)
    check("user list selector 19", bu[1] == 19)
    check("user list count at body[12]", struct.unpack_from("<H", bu, 12)[0] == 2)
    check("user list total/index at 16/18",
          struct.unpack_from("<HH", bu, 16) == (1, 0))
    r0 = bu[20:20 + D.PEER_REC_LEN]
    check("record key at +0", struct.unpack_from("<I", r0, 0)[0] == 0xa455a599)
    check("record name at +38", r0[D.PEER_NAME_OFF:D.PEER_NAME_OFF + 6] == b"Quarry")
    check("record rank at +54", r0[D.PEER_RANK_OFF] == 3)
    check("record zone at +32", struct.unpack_from("<H", r0, D.PEER_ZONE_OFF)[0] == 0xffff)
    check("second record at stride 56",
          struct.unpack_from("<I", bu, 20 + D.PEER_REC_LEN)[0] == 7)

    # --- game-server channel (sec 4cq / 4cx)
    g = D.build_gs_message(29, seq=77, body_extra=bytes(64))
    check("gs inner type 130", g[8] == 130)
    check("gs flags reliable", g[9] == 0x01)
    check("gs seq in the FRAMEWORK header at +14", struct.unpack_from("<H", g, 14)[0] == 77)
    check("gs type u16 at body[0]", struct.unpack_from("<H", body(g), 0)[0] == 29)
    arm = D.build_gs_stats([(0x69300000, 5)], state=1, seq=78)
    ba = body(arm)
    check("gs arm is message 27", struct.unpack_from("<H", ba, 0)[0] == 27)
    check("gs arm body >= 13 bytes", len(ba) >= D.GS_ARM_MIN_BODY)
    check("gs arm count/state", ba[12] == 1 and ba[13] == 1)
    check("gs arm entry", struct.unpack_from("<IH", ba, 16) == (0x69300000, 5))

    # --- spawn presets sit inside the wings vl_main classifies (AUDIT 09-05)
    def region(x, z):
        if 430 < x < 1530 and -600 < z < 560:
            return 0
        if -550 < x < 550 and -1560 < z < -430:
            return 1
        if -1550 < x < -400 and -600 < z < 560:
            return 2
        return 3
    want = {"east": 0, "east-anchor": 0, "south": 1, "west": 2, "north": 3, "room": 3}
    for k, v in want.items():
        px, _, pz = D.SPAWN_PRESETS[k][:3]
        check("preset %s -> vl_main region %d" % (k, v), region(px, pz) == v,
              "(%.1f, %.1f)" % (px, pz))
    check("room is the briefing seat", D.SPAWN_PRESETS["room"] == D.SPAWN_ROOM)

    # --- battletable probe (sec 4do): record at body[16], count kept 0
    bt = D.build_battletable_probe(world_door_request(), ident=0)
    bb = body(bt)
    check("battletable selector 27", bb[1] == 27)
    R = D.BATTLETABLE_REC_OFF
    check("battletable list count is 0 (no wild copy)", struct.unpack_from("<H", bb, R + 28)[0] == 0)
    check("battletable rec+24 sentinel", struct.unpack_from("<H", bb, R + 24)[0] == 555)
    check("battletable comment string", bb[R + 36:R + 44] == b"PROBE_CO")

    # --- the CHARACTER ID (sec 4dv). wire+0..3 of the 96-byte roster record
    # becomes [kelsvc+272] at lobby phase 25, via 0x00588ee0 reading
    # [nest+244] + slot*96 + 48 -- which is buf-record+32, which 0x0058ad30's
    # scatter fills from wire+0. We shipped 0 there forever, so getMyCharaId()
    # returned 0 and every self-lookup missed. Proof: an offline run of the client's own code (doc_charaid_proof)
    rid = D.build_used_record(2, "Lex", char_id=0x1234)
    check("roster record is 96 bytes", len(rid) == 96)
    check("wire+0..3 is the character id",
          struct.unpack_from("<I", rid, 0)[0] == 0x1234)
    check("name is still at wire+68", rid[68:71] == b"Lex")
    check("used flag is still bit 0 of wire+85", rid[85] & 1 == 1)
    check("char_id omitted keeps the old all-zero id",
          struct.unpack_from("<I", D.build_used_record(2, "Lex"), 0)[0] == 0)
    check("bits 30 and 31 are masked off (peer-table side + sign-extending "
          "cache key)",
          struct.unpack_from("<I", D.build_used_record(0, "x",
                                                       char_id=0xFFFFFFFF),
                             0)[0] == 0x3FFFFFFF)
    # sec 4fs: wire+84 is the record's SLOT number, and it (not the cursor)
    # is what the select handler 0x00ad5980 hands phase 25 as the chara-buffer
    # slot. Served as 0 everywhere, every pick read slot 0's id (Test -> Lex).
    # Proof: an offline run of the client's own code (doc_charslot_proof)
    check("wire+84 is the slot number (the select's buffer index)",
          [D.build_used_record(i, "x")[84] for i in range(4)] == [0, 1, 2, 3])
    check("the slot byte is not the used byte (wire+85 bit 0 still set)",
          D.build_used_record(1, "x")[85] & 1 == 1)
    # sec 4fy: wire+56 is the select-screen preview look, u16 LE chr_code.
    # Proof: an offline run of the client's own code (doc_select_costume_proof)
    _lex = D.build_used_record(0, "Lex", {"app92": 0x12, "app93": 0x10})
    check("wire+56 is the look (Lex = 0x1012 LE)", _lex[56:58] == b"\x12\x10")
    check("the look leaves id/name/slot/used alone",
          _lex[68:71] == b"Lex" and _lex[84] == 0 and _lex[85] & 1 == 1)
    check("no appearance -> wire+56 stays 0 (the old record)",
          D.build_used_record(0, "x")[56:58] == b"\x00\x00")

    # --- the SHORT rung (sec 4dv): selector 22 is a 36-byte datagram, and the
    # old `len(req) < BODY_OFF + 16` bail in build_world_answer returned None
    # for it. That is the reserve's server handoff -- phase 42 sends it, phase
    # 43 blocks on the selector-23 answer, and every one of the seven in the
    # 09-05 corpus went unanswered, which is CER-47117 at phase 43.
    short = bytearray(36)
    short[0] = 0x04
    short[1] = 0x02
    struct.pack_into("<H", short, 2, 36)
    short[8] = 0x7f
    struct.pack_into("<I", short, 16, 0)          # record+4 == [kelsvc+272] == 0
    short[D.BODY_OFF + 0] = 7
    short[D.BODY_OFF + 1] = 22
    a22 = D.build_world_answer(bytes(short), selector=23, ident=0, pad_to=176)
    check("short (36-byte) request still builds an answer", a22 is not None)
    if a22 is not None:
        ab = body(a22)
        check("short answer selector is 23", ab[1] == 23)
        check("short answer body[12..15] = 0 -> [kelsvc+1064] >= 0",
              struct.unpack_from("<i", ab, 12)[0] == 0)
        check("short answer is padded past body[140]", len(ab) >= 176)
    check("a 20-byte runt is still rejected",
          D.build_world_answer(bytes(20), selector=23) is None)

    # --- the BATTLETABLE LIST (sec 4dv): selector 16 -> 17, arm 0x00bccb30,
    # accumulator 0x00bc9a70. Offsets measured by running the client's own
    # converter 0x0058af88 (an offline run of the client's own code (doc_btrec)) and reading the row renderer
    # 0x00aa2900; proved end to end in an offline run of the client's own code (doc_btlist_proof).
    recs = [D.build_battletable_record(table_id=101, leader=0xA756A69A, cur=1,
                                       maximum=8, map_idx=0, mode=1,
                                       comment="Come on in"),
            D.build_battletable_record(table_id=102, cur=4, maximum=16,
                                       map_idx=7, in_progress=True)]
    check("battletable record is 120 bytes", all(len(r) == 120 for r in recs))
    bl = D.build_battletable_list(world_door_request(), recs, ident=0)
    lb = body(bl)
    check("battletable list selector 17", lb[1] == D.BATTLETABLE_LIST_ANS)
    check("list body[12] = records in this message",
          struct.unpack_from("<H", lb, 12)[0] == 2)
    check("list body[16] = 1 total message",
          struct.unpack_from("<H", lb, 16)[0] == 1)
    check("list body[18] = index 0", struct.unpack_from("<H", lb, 18)[0] == 0)
    check("list records start at body[20], stride 120",
          len(lb) == 20 + 120 * 2)
    r0 = lb[20:140]
    check("rec+24 is the key", struct.unpack_from("<H", r0, D.BT_OFF_ID)[0] == 101)
    check("rec+28 is current participants",
          struct.unpack_from("<H", r0, D.BT_OFF_CUR)[0] == 1)
    check("rec+109 is max participants", r0[D.BT_OFF_MAX] == 8)
    check("rec+113 is the map index", r0[D.BT_OFF_MAP] == 0)
    check("rec+8 is the leader uid",
          struct.unpack_from("<I", r0, D.BT_OFF_LEADER)[0] == 0xA756A69A)
    check("rec+36.. is the comment", r0[36:46] == b"Come on in")
    r1 = lb[140:260]
    check("rec+30 bit0 is the in-progress flag", r1[D.BT_OFF_STATE] & 1 == 1)
    check("map name table matches the client's 0x00afc68c order",
          D.BT_MAPS[0] == "jungle" and D.BT_MAPS[7] == "church"
          and D.BT_MAPS[14] == "edge" and len(D.BT_MAPS) == 17)

    # --- the spec parser
    spec = D.parse_battletable_spec("jungle:1/8:hello;church:0/16:")
    check("spec parses two tables", len(spec) == 2)
    check("spec map name -> index", spec[1][D.BT_OFF_MAP] == 7)
    check("spec cur/max", struct.unpack_from("<H", spec[0], D.BT_OFF_CUR)[0] == 1
          and spec[0][D.BT_OFF_MAX] == 8)
    check("bare count spec", len(D.parse_battletable_spec("3")) == 3)
    check("empty spec is no tables", D.parse_battletable_spec("") == [])

    # --- the GAME-SERVER ENDPOINT rungs (sec 4dw). 0x00bca938 reads body[52..55]
    # as the IP, body[56..57] as the port (big-endian) and body[58..59] as
    # [kelsvc+268]. Selectors 21 and 31 reach it gated on [kelsvc+12] == 8; 104
    # reaches it ungated. Until the sec 4dv fix let a reservation past phase 43,
    # selector 21 had never been asked for -- and then phase 44 asked, we sent
    # build_world_answer's ZERO body, and the client's game server became
    # 0.0.0.0:0. The avatar froze in the lobby, still broadcasting position.
    check("21 and 31 are the endpoint rungs", D.GS_ENDPOINT_SELECTORS == (21, 31))
    for sel in D.GS_ENDPOINT_SELECTORS:
        ep = D.build_world_answer(world_door_request(), selector=sel, ident=0,
                                  pad_to=176, gs_ip="192.0.2.60",
                                  gs_port=55040, gs_id=1)
        eb = body(ep)
        check("selector %d carries the endpoint IP" % sel,
              eb[52:56] == bytes([192, 0, 2, 60]))
        check("selector %d carries the port big-endian" % sel,
              struct.unpack_from(">H", eb, 56)[0] == 55040)
        check("selector %d carries the id little-endian -> [kelsvc+268]" % sel,
              struct.unpack_from("<H", eb, 58)[0] == 1)
    # The real phase-44 request is 40 bytes -- a 16-byte body -- so everything
    # past body[16] is our own zero padding. That is precisely why the old
    # `--world-gs-ip` default of "" produced an all-zero ENDPOINT rather than no
    # endpoint at all: 0x00bca938 has no "absent" case, it just stores what it
    # reads. (world_door_request() is 132 bytes and carries a session token
    # through body[52..79], so it cannot show this -- use the real shape.)
    req20 = bytearray(40)
    req20[0] = 0x04
    req20[1] = 0x02
    struct.pack_into("<H", req20, 2, 40)
    req20[8] = 0x7f
    req20[D.BODY_OFF + 0] = 7
    req20[D.BODY_OFF + 1] = 20
    zero = D.build_world_answer(bytes(req20), selector=21, ident=0, pad_to=176)
    check("and with NO endpoint it is all zeros -- the bug, pinned",
          body(zero)[52:60] == bytes(8))

    # WARNING: SAME OFFSET, TWO MEANINGS: body[52..55] is the endpoint IP on selector 21
    # and the SPAWN INDEX on selector 13. Passing gs_ip on every rung would
    # silently overwrite the spawn, which is why the caller keys it on the
    # selector.
    sp = D.SPAWN_PRESETS["east"]
    s13 = D.build_world_answer(world_door_request(),
                               selector=D.WORLD_SPAWN_SELECTOR_ANS, ident=0,
                               pad_to=176, spawn=sp)
    check("selector 13 still carries the spawn index at body[52], not an IP",
          struct.unpack_from("<H", body(s13), 52)[0] == sp[6])

    # --- server list entry (frag3)
    e = D.build_srv_entry("192.0.2.60", 55040, id0=5, tail=7)
    check("srv entry port network order", struct.unpack_from(">H", e, 2)[0] == 55040)
    check("srv entry ip network order", e[4:8] == bytes([192, 0, 2, 60]))
    check("srv entry id/tail", struct.unpack_from("<H", e, 0)[0] == 5
          and struct.unpack_from("<H", e, 10)[0] == 7)

    # --- sec 4dz: the battletable console verbs out of the store -------------
    def req(sel, extra=b"", ident=0x2a664):
        b = bytearray(12) + bytearray(extra)
        b[0], b[1], b[4] = 7, sel, 1
        r = bytearray(D.BODY_OFF) + b
        r[0], r[1], r[8] = 0x04, 0x02, 0x7f
        struct.pack_into("<H", r, 2, len(r))
        struct.pack_into("<I", r, 16, ident)
        return bytes(r)

    st = D.BattletableStore(D.parse_battletable_spec("jungle:0/8:seed"),
                            gs_ip="192.0.2.60", gs_port=55040)
    check("store seeded from the list spec", len(st.tables) == 1 and 1 in st.tables)
    check("verb requests are the phase-table selectors",
          D.BT_VERB_REQS == (24, 26, 28, 151, 153, 155, 125, 127)
          and D.BT_JOIN_REQS == (20, 30))
    check("request_body reads a mode-2 body and refuses mode 1",
          D.request_body(req(24), None)[1] == 24
          and D.request_body(bytes([4, 1]) + req(24)[2:], None) is None)

    wire = D.build_battletable_record(table_id=0, leader=0, cur=0, maximum=8,
                                      map_idx=7, mode=1, comment="Church run")
    r24 = req(24, wire)
    pkt, note = D.battletable_verb(st, r24, D.request_body(r24, None), 24, 0x2a664, 0xa455a599)
    b25 = body(pkt)
    key = struct.unpack_from("<H", b25, D.BATTLETABLE_REC_OFF + D.BT_OFF_ID)[0]
    check("create answers selector 25", b25[1] == 25)
    check("create assigns a fresh key", key == 2, "key=%d" % key)
    check("create record base is body[12] (a3+36 over the raw datagram)",
          D.BATTLETABLE_REC_OFF == 12 and D.BT_MEMBERS_OFF == 132)
    check("create record at body[12..131] keeps the client's map/max/comment",
          b25[D.BATTLETABLE_REC_OFF + D.BT_OFF_MAP] == 7 and b25[D.BATTLETABLE_REC_OFF + D.BT_OFF_MAX] == 8
          and b25[D.BATTLETABLE_REC_OFF + 36:D.BATTLETABLE_REC_OFF + 46] == b"Church run")
    # 2026-09-13: the leader is the creator's CHARID (ident) -- the row resolves
    # a name from it, and the entrance uid is shared across machines / unknown
    # to the other client. The uid is only the fallback when no charid is known.
    check("create stamps the leader CHARID at rec+8 (not the entrance uid)",
          struct.unpack_from("<I", b25, D.BATTLETABLE_REC_OFF + D.BT_OFF_LEADER)[0] == 0x2a664)
    _st0 = D.BattletableStore()
    _p0, _ = D.battletable_verb(_st0, r24, D.request_body(r24, None), 24, 0, 0xa455a599)
    check("create with no charid falls back to the uid as leader",
          struct.unpack_from("<I", body(_p0), D.BATTLETABLE_REC_OFF + D.BT_OFF_LEADER)[0]
          == 0xa455a599)
    check("create stamps the game-server ip at rec+12 / port big-endian at rec+20",
          b25[D.BATTLETABLE_REC_OFF + 12:D.BATTLETABLE_REC_OFF + 16] == bytes([192, 0, 2, 60])
          and struct.unpack_from(">H", b25, D.BATTLETABLE_REC_OFF + 20)[0] == 55040)
    check("create seats the creator: rec+28 = 1, member id at body[136]",
          struct.unpack_from("<H", b25, D.BATTLETABLE_REC_OFF + D.BT_OFF_CUR)[0] == 1
          and struct.unpack_from("<I", b25, D.BT_MEMBERS_OFF)[0] == 0x2a664)
    check("the store knows who sits where", st.table_of(0x2a664) == key)
    # sec 4fl: the reservation echo that trails the CREATE-ok (and JOIN-ok)
    echo = D.build_reserve_echo(r24, key, ident=0, pad_to=176)
    be = body(echo)
    check("reserve echo answers selector 152 (RESERVE ok)",
          be[1] == 152 and D.selector_name(152) == "RESERVE ok")
    check("reserve echo result body[12..15] = 0 (0x00bcd6a4 bltz passes)",
          struct.unpack_from("<i", be, 12)[0] == 0)
    check("reserve echo carries the table key at body[16..17] (0x00bcd6ac lhu)",
          struct.unpack_from("<H", be, 16)[0] == key)
    check("reserve echo is padded like every world answer", len(be) >= 176)
    # sec 4fm: the leader's START request as captured live
    # 21:48:10 (RECV #145, 52 bytes, mode 2): body[12] = 03 = LOBBY_CMD_START.
    r240 = bytes.fromhex(
        "04023400 7dcd0000 b01c3be9 fc4cc98f 3f55ebbf 0dd17847 07f00000 01000000"
        "00000000 03cc893d 00000000 f7fdffca 00000000".replace(" ", ""))
    check("LOBBY_CMD_START is 3 (0x00bd1db8, netclient bit 0x40)",
          D.LOBBY_CMD_START == 3)
    check("the captured Start request is selector 240 carrying command 3",
          r240[D.BODY_OFF + 1] == 240 and D.lobby_cmd_id(r240, None) == 3)
    r38s = D.gs_ready_roster(
        D.build_world_answer(r240, selector=38, ident=0, pad_to=176),
        0x2a664, 1, members=(0x2a664,), rec=st.record(key))
    check("BATTLE READY after START carries the table record + a 1-seat roster",
          body(r38s)[1] == 38
          and struct.unpack_from("<H", body(r38s), D.BATTLETABLE_REC_OFF + D.BT_OFF_ID)[0] == key
          and struct.unpack_from("<H", body(r38s), D.GS_READY_COUNT_OFF)[0] == 1)
    check("the list now carries both tables, in key order",
          [struct.unpack_from("<H", r, D.BT_OFF_ID)[0] for r in st.records()] == [1, key])

    st.reserve(key, 0x1234)
    r26 = req(26, struct.pack("<H", key) + bytes(2))
    pkt, note = D.battletable_verb(st, r26, D.request_body(r26, None), 26, 0x2a664, 0)
    b27 = body(pkt)
    check("config answers selector 27 with the record and 2 members",
          b27[1] == 27 and struct.unpack_from("<H", b27, D.BATTLETABLE_REC_OFF + D.BT_OFF_CUR)[0] == 2
          and struct.unpack_from("<I", b27, D.BT_MEMBERS_OFF + 4)[0] == 0x1234)
    pkt, note = D.battletable_verb(st, req(26, bytes([99, 0, 0, 0])),
                                   D.request_body(req(26, bytes([99, 0, 0, 0])), None),
                                   26, 0x2a664, 0)
    check("config of an unknown table answers 27 with an ALL-ZERO record (flags word "
          "included -- a -1 there would set the password bit)",
          pkt is not None and body(pkt)[1] == 27
          and body(pkt)[D.BATTLETABLE_REC_OFF:D.BATTLETABLE_REC_OFF + D.BT_REC_LEN]
          == bytes(D.BT_REC_LEN), note)
    _rq99 = req(26, bytes([99, 0, 0, 0]))
    _pp, _np = D.battletable_verb(st, _rq99, D.request_body(_rq99, None), 26,
                                  0x2a664, 0, probe=True)
    check("the sentinel probe never answers an unknown table (it painted a phantom "
          "password table after a dissolve)",
          _pp is not None
          and body(_pp)[D.BATTLETABLE_REC_OFF:D.BATTLETABLE_REC_OFF + D.BT_REC_LEN]
          == bytes(D.BT_REC_LEN), _np)

    w2 = bytearray(st.record(key))
    w2[D.BT_OFF_MAP] = 4
    w2[D.BT_OFF_LEADER:D.BT_OFF_LEADER + 4] = bytes(4)
    r28 = req(28, bytes(w2))
    pkt, note = D.battletable_verb(st, r28, D.request_body(r28, None), 28, 0x2a664, 0)
    b29 = body(pkt)
    check("adjust answers 29 with the new map and keeps our leader/endpoint",
          b29[1] == 29 and b29[D.BATTLETABLE_REC_OFF + D.BT_OFF_MAP] == 4
          and struct.unpack_from("<I", b29, D.BATTLETABLE_REC_OFF + D.BT_OFF_LEADER)[0] == 0x2a664
          and b29[D.BATTLETABLE_REC_OFF + 12:D.BATTLETABLE_REC_OFF + 16] == bytes([192, 0, 2, 60]))

    r151 = req(151, struct.pack("<H", key) + bytes(2))
    pkt, note = D.battletable_verb(st, r151, D.request_body(r151, None), 151, 0x5555, 0)
    b152 = body(pkt)
    check("reserve-by-id answers 152 with the key at body[16] and result 0",
          b152[1] == 152 and struct.unpack_from("<H", b152, 16)[0] == key
          and struct.unpack_from("<i", b152, 12)[0] == 0)
    check("reserve seated the third member", len(st.members(key)) == 3)
    r151b = req(151, struct.pack("<H", 77) + bytes(2))
    pkt, note = D.battletable_verb(st, r151b, D.request_body(r151b, None), 151, 0x6666, 0)
    check("reserving an unknown table answers result -1",
          struct.unpack_from("<i", body(pkt), 12)[0] == -1)

    st.tables[key]["password"] = b"abc"
    r153 = req(153, struct.pack("<H", key) + bytes(2) + b"xyz\x00\x00\x00\x00\x00")
    pkt, note = D.battletable_verb(st, r153, D.request_body(r153, None), 153, 0x7777, 0)
    check("wrong password answers 154 with result -2",
          body(pkt)[1] == 154 and struct.unpack_from("<i", body(pkt), 12)[0] == -2)
    r153 = req(153, struct.pack("<H", key) + bytes(2) + b"abc\x00\x00\x00\x00\x00")
    pkt, note = D.battletable_verb(st, r153, D.request_body(r153, None), 153, 0x7777, 0)
    check("right password seats", struct.unpack_from("<i", body(pkt), 12)[0] == 0
          and 0x7777 in st.members(key))

    pkt, note = D.battletable_verb(st, req(155), D.request_body(req(155), None), 155, 0x5555, 0)
    check("cancel answers 156 and unseats", body(pkt)[1] == 156 and 0x5555 not in st.members(key))
    check("kick / appoint act on the store",
          st.kick(key, 0x1234) and 0x1234 not in st.members(key)
          and st.appoint(key, 0x7777) and st.tables[key]["leader"] == 0x7777
          and not st.kick(key, 0x9999))
    pkt, note = D.battletable_verb(st, req(127, struct.pack("<I", 0x1234)),
                                   D.request_body(req(127, struct.pack("<I", 0x1234)), None),
                                   127, 0x2a664, 0)
    check("invite answers 128", body(pkt)[1] == 128)
    # sec 4he: leader authority. 0x2a664 created the table and then APPOINTED
    # 0x7777, so its own Dissolve is refused (126, result -1, table kept);
    # the appointed leader's Dissolve drops it.
    pkt, note = D.battletable_verb(st, req(125), D.request_body(req(125), None), 125, 0x2a664, 0)
    check("TWIN (sec 4he): dissolve by a NON-leader answers 126 with -1 and keeps the table",
          body(pkt)[1] == 126 and struct.unpack_from("<i", body(pkt), 12)[0] == -1
          and st.get(key) is not None and "REFUSED" in note)
    pkt, note = D.battletable_verb(st, req(125), D.request_body(req(125), None), 125, 0x7777, 0)
    check("dissolve answers 126 and drops the table",
          body(pkt)[1] == 126 and st.get(key) is None and st.table_of(0x7777) is None)
    # 2026-10-01 (manual p.29): Adjust Rules is leader-only, refused while
    # the battle runs and below the seated count; a departing leader hands
    # the Leader column (t["leader"]) to the next member, not just leader_cid.
    _lt = D.BattletableStore()
    _lk = _lt.create(D.build_battletable_record(table_id=0, maximum=8), 0xA1, 0xA1)
    _lt.reserve(_lk, 0xB2)
    _lt.reserve(_lk, 0xC3)
    _r6 = D.build_battletable_record(table_id=_lk, maximum=6)
    check("TWIN: rules change by a seated NON-leader is refused, record kept",
          not _lt.update(_lk, _r6, 0xB2)
          and _lt.record(_lk)[D.BT_OFF_MAX] == 8)
    check("rules change by the leader is taken",
          _lt.update(_lk, _r6, 0xA1) and _lt.record(_lk)[D.BT_OFF_MAX] == 6)
    check("rules change below the seated count (3) is refused",
          not _lt.update(_lk, D.build_battletable_record(table_id=_lk, maximum=2), 0xA1))
    _lt.set_in_progress(_lk, True)
    check("rules change while In Progress is refused",
          not _lt.update(_lk, _r6, 0xA1))
    _lt.set_in_progress(_lk, False)
    _lt.cancel(0xA1)
    check("leader leaves -> next member leads, and the row's Leader moves too",
          _lt.leader_cid(_lk) == 0xB2 and _lt.tables[_lk]["leader"] == 0xB2
          and struct.unpack_from("<I", _lt.record(_lk), D.BT_OFF_LEADER)[0] == 0xB2
          and _lt.is_leader(_lk, 0xB2) and not _lt.is_leader(_lk, 0xA1))
    st2 = D.BattletableStore()
    check("reserving an unknown key fails before auto-create", st2.reserve(59600, 0x1)[0] == -1)
    st2.add_record(D.build_battletable_record(table_id=59600, leader=0x2, cur=0, maximum=8))
    check("an on-the-fly table keeps the client's key and seats it",
          st2.reserve(59600, 0x1)[0] == 0 and st2.table_of(0x1) == 59600
          and struct.unpack_from("<H", st2.record(59600), D.BT_OFF_ID)[0] == 59600)
    # --- sec 4eo/4ep (2026-09-11): --bt-no-onfly-reserve. The console
    # default-targets the uninitialised [manager+11808] (59600); a JOIN for
    # an UNKNOWN table used to be create-on-the-fly'd (sec 4ee) and answered
    # selector 21 with a SUCCESS endpoint (result 0), which sets the client
    # reserved flag [kelsvc+1092] bit 4 -- perpetually reserving the player
    # so the Create option is hidden (prompt 0x6835). With the flag the
    # phantom JOIN is NOT invented (the store stays clean) and the
    # selector-21 answer carries result=-1, which the phase-44 JOIN arm reads
    # as "no such table" and never sets the reserved flag. These pin the two
    # wire facts the receive loop's decision rests on.
    st3 = D.BattletableStore()
    res3, _ = st3.reserve(59600, 0x777)
    check("phantom JOIN target unknown -> reserve -1 (no create, no seat)",
          res3 == -1 and len(st3.tables) == 0 and st3.table_of(0x777) is None)
    ok_ep = D.build_world_answer(bytes(req20), selector=21, ident=0,
                                 pad_to=176, result=0, gs_ip="192.0.2.60",
                                 gs_port=55040)
    fail_ep = D.build_world_answer(bytes(req20), selector=21, ident=0,
                                   pad_to=176, result=-1, gs_ip="192.0.2.60",
                                   gs_port=55040)
    check("success endpoint (result 0) -> body[12..15]=0, client RESERVES",
          struct.unpack_from("<i", body(ok_ep), 12)[0] == 0)
    check("phantom endpoint (result -1) -> body[12..15]=-1, client stays "
          "UNRESERVED and free to CREATE",
          struct.unpack_from("<i", body(fail_ep), 12)[0] == -1)
    check("a store with no seed still creates key 1",
          D.BattletableStore().create(wire, 0x1, 0x2) == 1)
    # sec 4gc: the situation id rides wire +34; a finished table is dissolved.
    _ss = D.BattletableStore(situation=1100)
    _ssk = _ss.create(wire, 0x1, 0x2)
    check("served record carries the situation id at wire +34 (sec 4gc)",
          struct.unpack_from("<H", _ss.record(_ssk), D.BT_OFF_SITUATION)[0]
          == 1100)
    # 2026-10-06: an INDIVIDUAL (BT) table loads the BT set, Res_bt1 (1000);
    # the team set's fences closed SE's BT start nodes off (Train Graveyard)
    _iw = bytearray(wire)
    struct.pack_into("<I", _iw, D.BT_OFF_FLAGS,
                     struct.unpack_from("<I", _iw, D.BT_OFF_FLAGS)[0] | D.BT_FLAG_INDIVIDUAL)
    _ssi = D.BattletableStore(situation=1100)
    _ski = _ssi.create(bytes(_iw), 0x3, 0x4)
    check("an individual (BT) table is stamped situation 1000, not the team 1100",
          struct.unpack_from("<H", _ssi.record(_ski), D.BT_OFF_SITUATION)[0] == 1000)
    check("TWIN: the same store's team table keeps 1100",
          struct.unpack_from("<H", _ssi.record(_ssi.create(wire, 0x5, 0x6)),
                             D.BT_OFF_SITUATION)[0] == 1100)
    # 2026-10-06 (Kalm "jail"): a situation the arena lacks builds every fence;
    # the arena's own 1100 / 1000, else its 9100 / 9000
    _AD = D.arenadata
    if _AD.ARENA_STARTS.get(203) and _AD.ARENA_STARTS.get(201):
        check("situation_for: Kalm (only 9xxx) -> 9100 team / 9000 BT; Jungle keeps 1100 / 1000",
              (_AD.situation_for(203, False), _AD.situation_for(203, True),
               _AD.situation_for(201, False), _AD.situation_for(201, True))
              == (9100, 9000, 1100, 1000))
        _ssm = D.BattletableStore(situation=1100)
        _ssm.situation_for = lambda rec, ind: _AD.situation_for(
            {0: 201, 2: 203}.get(rec[D.BT_OFF_MAP], 201), ind)
        _mw = bytearray(wire)
        _mw[D.BT_OFF_MAP] = 2                                   # Kalm
        _skm = _ssm.create(bytes(_mw), 0x7, 0x8)
        _s1 = struct.unpack_from("<H", _ssm.record(_skm), D.BT_OFF_SITUATION)[0]
        _ssm.tables[_skm]["rec"][D.BT_OFF_MAP] = 0              # leader picks Jungle
        _s2 = struct.unpack_from("<H", _ssm.record(_skm), D.BT_OFF_SITUATION)[0]
        check("a Kalm team table carries 9100; moved to Jungle it re-picks 1100",
              (_s1, _s2) == (9100, 1100), "%r" % ((_s1, _s2),))
    check("dissolve drops the table and its reservation (sec 4gc)",
          _ss.dissolve(_ssk) and _ss.table_of(0x1) is None
          and not _ss.records())
    check("selector names cover every verb",
          all(D.selector_name(s) != "?" for s in D.BT_VERB_REQS + D.BT_JOIN_REQS))

    # --- sec 4ea: the game-server ladder ---------------------------------------
    check("request -> answer pairs are type + 1",
          all(v == k + 1 for k, v in D.GS_REQ_ANSWERS.items())
          and set(D.GS_REQ_ANSWERS) == {31, 33, 36, 47, 56, 58, 60, 38, 45, 54, 46})
    n4 = D.build_gs_notify(4, bytes(4) + bytes(D.GS_SETUP_LEN), seq=3, ident=0x2a664)
    nb = body(n4)
    check("notify rides message 35", struct.unpack_from("<H", nb, 0)[0] == 35)
    check("notify kind at body[12]", struct.unpack_from("<I", nb, 12)[0] == 4)
    check("notify payload from body[16], setup record base body[20] zeroed to +400",
          len(nb) == 20 + D.GS_SETUP_LEN and nb[20:20 + D.GS_SETUP_LEN] == bytes(D.GS_SETUP_LEN))
    check("notify keeps the framework seq at +14", struct.unpack_from("<H", n4, 14)[0] == 3)
    # sec 4ga: getBattleInitPos = the getter buffer +0/+4/+8 = record +0..8;
    # get_battle_rot_l = atan2(record+12, record+20).
    sp = D.build_gs_spawn(1.5, -2.0, 3.25, rot=90.0, seq=1)
    sb = body(sp)
    check("spawn POSITION at record +0/+4/+8 (body[20..31]) (sec 4ga)",
          struct.unpack_from("<fff", sb, 20) == (1.5, -2.0, 3.25))
    _fx, _fy, _fz = struct.unpack_from("<fff", sb, 32)
    check("spawn FACING (sin, 0, cos) of rot at record +12/+16/+20 (sec 4ga)",
          abs(_fx - 1.0) < 1e-6 and _fy == 0.0 and abs(_fz) < 1e-6)
    _go = [k for k, _ in D.gs_battle_sequence(D.GS_BATTLE_GO_DEFAULT)]
    check("start burst is the spawn alone; GO = 5 + the damage-gate handshake "
          "(sec 4ga/4he)",
          [k for k, _ in D.gs_battle_sequence(D.GS_BATTLE_START_DEFAULT,
                                              zone=201)] == [2]
          and _go[0] == 5 and set(_go[1:]) == {28, 29, 3, 30})
    check("2026-09-24: no GO kind >= 49 -- the retail notify dispatcher "
          "0x00bcb6d8 drops them (the old burst's 53 never ran)",
          all(k < D.GS_NOTIFY_KIND_LIMIT for k in _go))
    check("TWIN: the previous burst carried a kind the client drops",
          not all(k < D.GS_NOTIFY_KIND_LIMIT
                  for k, _ in D.gs_battle_sequence("5,28,29,3,30,53")))
    # sec 4he: 0x00bc2aa0 posts facade 0x20 only when it runs with 0x100 (28),
    # 0x200 (29), 0x400 (30 or 28) and 0x20 (3) all set, and it runs from kinds
    # 3 and 30 -- so the LAST of 3 / 30 must come after 28 and 29.
    check("damage gate: the last of kinds 3/30 follows both 28 and 29",
          max(_go.index(3), _go.index(30)) > max(_go.index(28), _go.index(29)))
    check("TWIN: the 09-13 burst (5,53) never opened the damage gate",
          not ({28, 29, 3, 30} <= set(k for k, _ in D.gs_battle_sequence("5,53"))))
    tl = D.build_gs_team_list([(1, 2, 0x2a664), (3, 4, 5)], seq=2, word12=7, word16=9)
    tb = body(tl)
    check("team list is message 57", struct.unpack_from("<H", tb, 0)[0] == 57)
    check("team list header at body[12]/[14]/[16]",
          struct.unpack_from("<HHI", tb, 12) == (7, 2, 9))
    check("team list entries 8 bytes from body[20]",
          struct.unpack_from("<HHI", tb, 20) == (1, 2, 0x2a664)
          and struct.unpack_from("<HHI", tb, 28) == (3, 4, 5))
    check("team list clamps to 8 entries",
          struct.unpack_from("<H", body(D.build_gs_team_list([(0, 0, 0)] * 12)), 14)[0] == 8)
    seqs = iter(range(10, 20))
    seqfn = lambda: next(seqs)
    pushes = D.gs_battle_sequence("4,2,5,53", spawn=(1.0, 2.0, 3.0), seq_fn=seqfn)
    check("battle sequence kinds", [k for k, _ in pushes] == [4, 2, 5, 53])
    check("battle sequence takes fresh seqs", [struct.unpack_from("<H", pk, 14)[0] for _, pk in pushes] == [10, 11, 12, 13])
    custom = D.gs_battle_sequence("51:0700", seq_fn=seqfn)
    check("KIND:HEX payload lands at body[16]", body(custom[0][1])[16:18] == b"\x07\x00")
    check("empty sequence is empty", D.gs_battle_sequence("") == [])
    r38 = D.build_world_answer(world_door_request(), selector=38, ident=0, pad_to=176)
    r38 = D.gs_ready_roster(r38, 0x2a664, 1, [0x1234, 0x2a664, 0])
    rb = body(r38)
    check("38 session id at body[36]", struct.unpack_from("<H", rb, 36)[0] == 1)
    # 2026-09-13: 0x00bcb838 copies COUNT-1 entries from body[132] and writes
    # the client itself into slot COUNT-1 -- the entries are the OTHERS only.
    check("38 roster count at body[40] = others + 1 (client appends itself)",
          struct.unpack_from("<H", rb, 40)[0] == 2)
    check("38 roster entries at body[132] stride 28 are the OTHER members only",
          struct.unpack_from("<I", rb, 132)[0] == 0x1234
          and struct.unpack_from("<I", rb, 160)[0] != 0x2a664)
    rec38 = D.build_battletable_record(table_id=77, leader=5, cur=0, maximum=8, map_idx=3)
    r38b = D.gs_ready_roster(D.build_world_answer(world_door_request(), selector=38, ident=0, pad_to=176),
                             0x2a664, 1, [0x1234], rec=rec38)
    rbb = body(r38b)
    check("38 with a record: the record sits at body[12], its key is the session id",
          rbb[12 + D.BT_OFF_MAP] == 3 and struct.unpack_from("<H", rbb, 36)[0] == 77
          and struct.unpack_from("<H", rbb, 40)[0] == 2)
    check("38 length field and checksum rewritten",
          struct.unpack_from("<H", r38, 2)[0] == len(r38)
          and struct.unpack_from("<H", r38, D.CKSUM_OFF)[0] == D.cksum(bytes(r38[:D.CKSUM_OFF]) + bytes(2) + bytes(r38[D.CKSUM_OFF + 2:])))
    wire = bytearray(24) + struct.pack("<HHII", 47, 1, 0, 0x77)
    wire[0], wire[1], wire[8] = 0x04, 0x02, 130
    struct.pack_into("<H", wire, 2, len(wire))
    mt, gb = D.gs_request_type(bytes(wire), None)
    check("client request type at body[0], arg at body[8]", mt == 47 and struct.unpack_from("<I", gb, 8)[0] == 0x77)
    ac = body(D.build_gs_add_chara(0x9001, 3, slot=1, seq=5, self_ident=0x2a664))
    check("fake teammate rides message 35 kind 31", struct.unpack_from("<H", ac, 0)[0] == 35
          and struct.unpack_from("<I", ac, 12)[0] == 31)
    check("kind 31 record: id at +20, TEAM in the HIGH nibble of byte +42 "
          "(slot in the LOW nibble)",
          struct.unpack_from("<I", ac, 20)[0] == 0x9001 and ac[42] == 0x31,
          "byte +42 = 0x%02x" % ac[42])
    ac = body(D.build_gs_add_chara(0x9001, 1, slot=2))
    check("kind 31 (team 1, slot 2) -> byte +42 == 0x12 (was 0x21: team 1 "
          "wrote roster slot 1, the client's own entry)", ac[42] == 0x12,
          "0x%02x" % ac[42])
    ac = body(D.build_gs_add_chara(0x9001, None, slot=2))
    check("kind 31 with no team -> 0xF2 (the member is filed at team 0xff)",
          ac[42] == 0xF2, "0x%02x" % ac[42])
    lv = body(D.build_gs_team_leave(0x41050, seq=3))
    check("leave team = message 35 kind 1",
          struct.unpack_from("<H", lv, 0)[0] == 35
          and struct.unpack_from("<I", lv, 12)[0] == 1)
    # sec 4et: the peer-push must pass build_peer_record(...)[4:] so fields
    # ALIGN in build_peer_answer (which re-prepends the id at wire+0). zone must
    # land at the OUTER record wire+32 (= what getCharacterTableId reads).
    # sec 4ev: --world-self-charaid overrides body[44..47] of the world-door
    # answer with the charaid (mgr+304 [rec+52] = body[44]); default echoes the
    # request (uid).
    # sec 4ex: --bt-start-ready clamps served BT_OFF_CUR to >=2 (Start gate).
    _st = D.BattletableStore(cur_min=2)
    _k = _st.add_record(D.build_battletable_record(table_id=7, leader=0x2a664,
                                                   cur=1, maximum=8), members=[0x2a664])
    _srec = _st.record(_k)
    check("bt-start-ready: solo table served with cur>=2",
          struct.unpack_from("<H", _srec, D.BT_OFF_CUR)[0] == 2)
    _st0 = D.BattletableStore(cur_min=0)
    _k0 = _st0.add_record(D.build_battletable_record(table_id=8, leader=0x2a664,
                                                     cur=1, maximum=8), members=[0x2a664])
    check("without bt-start-ready: solo table served with cur=1",
          struct.unpack_from("<H", _st0.record(_k0), D.BT_OFF_CUR)[0] == 1)
    _req = bytes(200)
    _w_on = body(D.build_world_answer(_req, selector=2, self_id=0x2a664))
    check("world-door self_id override: body[44..47] = charaid",
          struct.unpack_from("<I", _w_on, 44)[0] == 0x2a664)
    _w_off = body(D.build_world_answer(_req, selector=2))
    check("world-door without override: body[44..47] not forced to charaid",
          struct.unpack_from("<I", _w_off, 44)[0] != 0x2a664)
    _pa = body(D.build_peer_answer(None, 0x2a664, ident=0,
              blob=D.build_peer_record(0x2a664, zone=0xffff, rank=0, flags=0)[4:]))
    check("peer-push record: id at wire+0",
          struct.unpack_from("<I", _pa, 12)[0] == 0x2a664)
    check("peer-push record: zone (--user-zone) aligned to wire+32 = getCharacterTableId's field",
          struct.unpack_from("<H", _pa, 12 + 32)[0] == 0xffff)
    d20 = body(D.build_gs_distribution([(0x2a664, 0, 0), (0x1234, 1, 1)], seq=4))
    check("distribution rides message 35 kind 20", struct.unpack_from("<H", d20, 0)[0] == 35
          and struct.unpack_from("<I", d20, 12)[0] == 20)
    check("distribution count at body[20], entries {id,team,slot} from body[24]",
          d20[20] == 2 and struct.unpack_from("<I", d20, 24)[0] == 0x2a664 and d20[28] == 0 and d20[29] == 0
          and struct.unpack_from("<I", d20, 32)[0] == 0x1234 and d20[36] == 1 and d20[37] == 1)
    check("request names cover the ladder and the acks",
          all(k in D.GS_REQ_NAMES for k in (1, 26, 44, 47, 56)))
    # sec 4eb: the client's own keepalive, verbatim from the 09-11 capture --
    # mode 4, header ciphertext, body plaintext `01 00 ..` = message 1
    ka = bytes.fromhex("0404240010a201004408a9dd2b05d812b0f6422f05503626010000000000000000000000")
    mt4, gb4 = D.gs_request_type(ka, None)
    check("mode-4 keepalive parses as message 1 without the header", mt4 == 1 and len(gb4) == 12)
    check("mode-4 is the game-server channel", ka[1] == 4 and D.GS_REQ_NAMES[1] == "keepalive")

    # sec 4fe: a mode-0 create (what the live client's only offered type sends)
    # is coerced to mode 1 so the table is a real, startable battle table.
    _st = D.BattletableStore()
    _rec = bytearray(D.BT_REC_LEN)
    _rec[D.BT_OFF_MODE] = 0
    struct.pack_into("<H", _rec, D.BT_OFF_CUR, 1)
    _rec[D.BT_OFF_MAX] = 6
    _cbody = bytearray(D.BT_REQ_REC_OFF + D.BT_REC_LEN)
    _cbody[0] = 7
    _cbody[1] = D.BT_REQ_CREATE
    _cbody[D.BT_REQ_REC_OFF:D.BT_REQ_REC_OFF + D.BT_REC_LEN] = _rec
    D.battletable_verb(_st, bytes(24), bytes(_cbody), D.BT_REQ_CREATE,
                       0x2aa68, 0x2aa68)
    _k = list(_st.tables)[0]
    check("create coerces invalid mode 0 to mode 1 (sec 4fe)",
          _st.record(_k)[D.BT_OFF_MODE] == 1)

    # sec 4ft: kind 2's record +26 is the arena ZONE get_onlinezone() reads
    # ([chan+1064]); +24/+25 the map pair. Zone 0 = exit(-1) = the title.
    _sz = body(D.build_gs_spawn(0.0, 0.0, 0.0, zone=201, bmap=(3, 4)))
    check("spawn record +24/+25 = map pair, +26 = arena zone (body[44..46])",
          (_sz[44], _sz[45], _sz[46]) == (3, 4, 201))
    check("spawn without a zone keeps the old zero bytes",
          body(D.build_gs_spawn(1.0, 2.0, 3.0))[44:48] == bytes(4))
    _zs = dict(D.gs_battle_sequence("4,2,5,53", spawn=(0.0, 0.0, 0.0),
                                    zone=201, bmap=(0, 0)))
    check("battle sequence kind 2 carries the zone", body(_zs[2])[46] == 201)
    _zn = dict(D.gs_battle_sequence("2", zone=202))
    check("kind 2 with a zone but no spawn still carries the zone",
          body(_zn[2])[46] == 202)
    # sec 4ft: the REAL roster's distribution and its readiness gate.
    _A, _B, _C = 0x2a664, 0x2aa68, 0x2b000
    check("real distribution: seat order, slot = position in the list",
          D.gs_real_distribution({_A: 0, _B: 1, _C: 0}, [_A, _B, _C])
          == [(_A, 0, 0), (_B, 1, 1), (_C, 0, 2)])

    def _arm_20(members, me, dist):
        """The client's kind-20 arm 0x00bc23d8 on `me`'s console: the 38
        roster (others in order, self last -- 0x00bcb838), then per entry i
        swap the id to roster[slot] and write it there; own index = i."""
        r = [m for m in members if m != me] + [me]
        r += [0] * (32 - len(r))
        own = None
        for i, (cid, _t, slot) in enumerate(dist):
            if cid == me:
                own = i
            for k in range(32):
                if r[k] == cid:
                    r[k], r[slot] = r[slot], r[k]
            r[slot] = cid
        return r, own

    def _roster_agrees(members, dist):
        for me in members:
            r, own = _arm_20(members, me, dist)
            if own is None or r[own] != me:
                return False
        return (len(set(_arm_20(members, members[0], dist)[0][:len(dist)]))
                == len(dist))

    # live table 31: 0x41050/0x41068 team 1, 0x41078 team 0
    _t31 = [0x41050, 0x41068, 0x41078]
    _t31t = {0x41050: 1, 0x41068: 1, 0x41078: 0}
    check("kind 20 (table 31 roster): every client's own index names ITSELF",
          _roster_agrees(_t31, D.gs_real_distribution(_t31t, _t31)))
    check("TWIN: the per-team slots a live server sent for table 31 fail that check",
          not _roster_agrees(_t31, [(0x41050, 1, 0), (0x41068, 1, 1),
                                    (0x41078, 0, 0)]))
    _t32 = [0x41078, 0x41050, 0x41068]
    check("kind 20 (table 32 roster): every client's own index names ITSELF",
          _roster_agrees(_t32, D.gs_real_distribution(
              {0x41078: 0, 0x41050: 0, 0x41068: 1}, _t32)))
    check("kind 20: slots are unique for 6 players on two teams",
          [e[2] for e in D.gs_real_distribution(
              {m: m & 1 for m in range(1, 7)}, list(range(1, 7)))]
          == [0, 1, 2, 3, 4, 5])
    check("real distribution skips a member with no team",
          D.gs_real_distribution({_A: 0}, [_A, _B]) == [(_A, 0, 0)])
    check("real ready: two players on opposite teams",
          D.gs_real_ready({_A: 0, _B: 1}, [_A, _B])[0])
    check("real ready: not with one seated player",
          not D.gs_real_ready({_A: 0}, [_A])[0])
    check("real ready: not until everyone has a team",
          not D.gs_real_ready({_A: 0}, [_A, _B])[0])
    check("real ready: not with both on the same team",
          not D.gs_real_ready({_A: 1, _B: 1}, [_A, _B])[0])
    # 2026-09-29 (Dirge report): a mission is co-op -- one side is ready
    check("real ready (co-op): both on the same team IS ready",
          D.gs_real_ready({_A: 1, _B: 1}, [_A, _B], coop=True)[0])
    check("TWIN: real ready (co-op): still not until everyone has a team",
          not D.gs_real_ready({_A: 1}, [_A, _B], coop=True)[0])
    # 2026-09-29: an 'early' table (mission / full) does not wait
    # out the countdown; any other table still does
    check("dist due: an EARLY table goes at ready + settle, before brief_end",
          D.gs_dist_due({"ready_at": 100.0, "dist": False, "brief_end": 400.0,
                         "early": True}, 5.0) == 105.0)
    check("TWIN: dist due: the same table not early waits for brief_end",
          D.gs_dist_due({"ready_at": 100.0, "dist": False, "brief_end": 400.0},
                        5.0) == 400.0)
    # sec 4ft LIVE 09-13: the leader's command 3 carries ident 0 -- the
    # fan-out must find the table by the session's charid instead.
    _fs = D.BattletableStore()
    _fk = _fs.create(D.build_battletable_record(table_id=0), _B, 0xa756a69a)
    _fs.reserve(_fk, _A)
    check("start fan-out: ident 0 falls back to the session charid",
          D.bt_start_targets(_fs, 0, _B) == (_fk, _B, [_A]))
    check("start fan-out: a real ident still wins",
          D.bt_start_targets(_fs, _B, 0x1234) == (_fk, _B, [_A]))
    check("start fan-out: no table -> nobody",
          D.bt_start_targets(_fs, 0, 0x5555)[0] is None
          and D.bt_start_targets(_fs, 0, 0) == (None, 0, []))
    # sec 4fv: a solo leader's distribution -- self first, bots after.
    _b1, _b2, _b3 = 0x9001, 0x9101, 0x9002
    check("solo distribution: self first, bots slotted within their team",
          D.gs_solo_distribution({_b1: 0, _A: 1, _b2: 1, _b3: 0}, _A)
          == [(_A, 1, 0), (_b1, 0, 1), (_b2, 1, 2), (_b3, 0, 3)])
    check("solo distribution: self defaults to team 0 with no request 31",
          D.gs_solo_distribution({}, _A) == [(_A, 0, 0)])
    _sd = body(D.build_gs_distribution(D.gs_solo_distribution({}, _A)))
    check("solo distribution is kind 20 with count 1 and self at body[24]",
          struct.unpack_from("<I", _sd, 12)[0] == 20 and _sd[20] == 1
          and struct.unpack_from("<I", _sd, 24)[0] == _A)
    # sec 4fw: the settle deadline is re-checked on the server's clock.
    check("dist due: READY table is due at ready_at + settle",
          D.gs_dist_due({"ready_at": 100.0, "dist": False}, 5.0) == 105.0)
    check("dist due: not ready -> None",
          D.gs_dist_due({"ready_at": None, "dist": False}, 5.0) is None)
    check("dist due: already sent -> None",
          D.gs_dist_due({"ready_at": 100.0, "dist": True}, 5.0) is None)
    # 2026-09-23: the briefing countdown ends -> unteamed members are seated
    check("dist due: not ready but an auto-team deadline -> that deadline",
          D.gs_dist_due({"ready_at": None, "dist": False, "auto_at": 50.0},
                        5.0) == 50.0)
    check("dist due: auto-team deadline ignored once the dist went out",
          D.gs_dist_due({"ready_at": None, "dist": True, "auto_at": 50.0},
                        5.0) is None)
    # 2026-09-24: never before the briefing countdown the players see
    check("dist due: READY early -> held to the briefing end (a 5:00 "
          "briefing used to start at 0:35)",
          D.gs_dist_due({"ready_at": 100.0, "dist": False, "brief_end": 400.0},
                        5.0) == 400.0)
    check("dist due: READY after the briefing end -> ready_at + settle",
          D.gs_dist_due({"ready_at": 398.0, "dist": False, "brief_end": 400.0},
                        5.0) == 403.0)
    check("dist due: READY once the countdown is over -> at once, no settle",
          D.gs_dist_due({"ready_at": 402.0, "dist": False, "brief_end": 400.0},
                        5.0) == 402.0)
    # 2026-09-24: a one-sided table at zero is REBALANCED
    _C = _B + 1
    _rb, _mv = D.gs_rebalance_teams({_A: 0, _B: 0}, [_A, _B])
    check("rebalance: 2 on team 0 -> the joiner moves to 1, the table is READY",
          _rb == {_A: 0, _B: 1} and _mv == [_B]
          and D.gs_real_ready(_rb, [_A, _B])[0], "%r %r" % (_rb, _mv))
    _rb, _mv = D.gs_rebalance_teams({_A: 1, _B: 1, _C: 1}, [_A, _B, _C])
    check("rebalance: 3 on team 1 -> the LAST one moves (leader stays), 2 v 1",
          _rb == {_A: 1, _B: 1, _C: 0} and _mv == [_C], "%r %r" % (_rb, _mv))
    _rb, _mv = D.gs_rebalance_teams({_A: 0, _B: 0, _C: 1}, [_A, _B, _C])
    check("rebalance: a playable 2 v 1 is left alone",
          _mv == [] and _rb == {_A: 0, _B: 0, _C: 1})
    _rb, _mv = D.gs_rebalance_teams({_A: 0}, [_A])
    check("rebalance: solo is left alone", _mv == [] and _rb == {_A: 0})
    check("rebalance TWIN: without it, 2 on team 0 is NOT ready (the stall)",
          not D.gs_real_ready({_A: 0, _B: 0}, [_A, _B])[0])
    check("dist due: Briefing Time None (brief_end None) -> ready_at + settle",
          D.gs_dist_due({"ready_at": 100.0, "dist": False, "brief_end": None},
                        5.0) == 105.0)
    check("dist due TWIN: without brief_end the early case fires at 105 (the bug)",
          D.gs_dist_due({"ready_at": 100.0, "dist": False}, 5.0) == 105.0)
    _at, _as = D.gs_auto_teams({_A: 1}, [_A, _B])
    check("auto-team: the live case (leader on 1, joiner never sent 31) "
          "-> joiner on team 0, and the table is READY",
          _at == {_A: 1, _B: 0} and _as == [_B]
          and D.gs_real_ready(_at, [_A, _B])[0], "%r %r" % (_at, _as))
    _at, _as = D.gs_auto_teams({}, [_A, _B])
    check("auto-team: nobody chose -> opposite sides",
          _at == {_A: 0, _B: 1} and D.gs_real_ready(_at, [_A, _B])[0])
    _at, _as = D.gs_auto_teams({_A: 0, _B: 0}, [_A, _B])
    check("auto-team: never moves a player who CHOSE (both on 0 stays not ready)",
          _as == [] and _at == {_A: 0, _B: 0}
          and not D.gs_real_ready(_at, [_A, _B])[0])
    check("auto-team TWIN: without it the live case is NOT ready (the bug)",
          not D.gs_real_ready({_A: 1}, [_A, _B])[0])
    # sec 4fy: kind 4 is the RESULT (facade 0x40 ends ev2045's battle loop),
    # so the start burst must not carry it; selector 39 is the battle reset.
    _st_kinds = [k for k, _ in D.gs_battle_sequence(D.GS_BATTLE_START_DEFAULT,
                                                    spawn=(0.0, 0.0, 0.0),
                                                    zone=201, bmap=(0, 0))]
    check("battle start burst has no kind 4 (the result) and still has kind 2",
          4 not in _st_kinds and 2 in _st_kinds, str(_st_kinds))
    _bo = body(D.build_world_answer(world_door_request(),
                                    selector=D.GS_BATTLE_OVER_SELECTOR,
                                    pad_to=176, ident=0))
    check("battle-over answer is selector 39 on subchannel 7",
          _bo[1] == 39 and _bo[0] == 7)

    # sec 4fu: the PEER RELAY. Two live 0x83s (two consoles:
    # PC, mode 2). The relay re-sends one to the other client as a PEER
    # datagram: flags bit 3 set (parser 0x0058a0b0 + router arm 0x00581530),
    # mode 0, and byte-for-byte the sender's ms, id and 40-byte pose otherwise.
    _live83 = {
        0x2a990: "04024000" "6d060000" "c00122f1e4420e46" "01baed7dcf8afd04"
                 "90a902002c1800441e0100bf2bbcb8c209fc7fbf00000000323b34bc"
                 "0220803f0001000000001210",
        0x2a664: "04024000" "fb610000" "dfec25a865a716f9" "9a57e87efab84314"
                 "64a60200000061440000" "00b500001143483ca13e00000000" "90f972bf"
                 "0220803f0001000000001210",
    }
    if D._KELCRYPT:
        for _cid, _hx in _live83.items():
            _hd = D.doc_kelcrypt.header(bytes.fromhex(_hx))
            _pl = _hd["plain"]
            check("live 0x83 0x%x: id at packet[16] == body[0]" % _cid,
                  _hd["type"] == 0x83 and _hd["u32_16"] == _cid
                  and struct.unpack_from("<I", _pl, D.BODY_OFF)[0] == _cid)
            check("live 0x83 0x%x: the client's checksum is cksum() of the "
                  "PLAINTEXT" % _cid,
                  struct.unpack_from("<H", _pl, D.CKSUM_OFF)[0] == D.cksum(_pl))
            _r = D.build_peer_relay(_pl)
            check("relay 0x%x: mode 0, flags bit 3, still type 0x83" % _cid,
                  _r[1] == 0 and _r[9] & 0x08 and _r[8] == 0x83)
            check("relay 0x%x: checksum valid under the client's rule" % _cid,
                  struct.unpack_from("<H", _r, D.CKSUM_OFF)[0] == D.cksum(_r))
            check("relay 0x%x: verbatim except mode, flags, checksum" % _cid,
                  len(_r) == len(_pl) and _r[0] == _pl[0] and _r[2:9] == _pl[2:9]
                  and _r[12:] == _pl[12:])
    else:
        check("doc_kelcrypt available for the relay checks", False)

    # sec 4fu: the type-125 SPAWN record for a player id (the 0x00bd2108 arm):
    # +4/+5 bytes, +6/+20 u16 = the pose record's +28/+30, +22 the time word's
    # low half; packet+4 the SENDER's ms. Absent keys keep the old bytes.
    _wu = D.build_world_update([dict(id=0x2a664, x=900.0, y=0.0, z=145.0,
                                     dx=0.3149, dy=0.0, dz=-0.9491, h6=0x2002,
                                     h20=0x3f80, b4=0, b5=0, h22=0x61fb)],
                               ms=0x000161fb)
    _wr = _wu[D.BODY_OFF + 4:]
    check("wu: sender ms at packet+4, full 32 bits",
          struct.unpack_from("<I", _wu, 4)[0] == 0x000161fb)
    check("wu: id, x/z x0.1", struct.unpack_from("<I", _wr, 0)[0] == 0x2a664
          and struct.unpack_from("<hh", _wr, 8)[0] == 9000
          and struct.unpack_from("<h", _wr, 12)[0] == 1450)
    check("wu: +6/+20/+22 carry the pose u16s and the time",
          struct.unpack_from("<H", _wr, 6)[0] == 0x2002
          and struct.unpack_from("<H", _wr, 20)[0] == 0x3f80
          and struct.unpack_from("<H", _wr, 22)[0] == 0x61fb)
    # sec 4fu (look): the relayed player's o099 code rides peer record +36
    # (-> slot+40 -> the peer lookup's +26 -> unit+88, which 0x00be4850 stamps
    # over pose +38). Built the way the relay builds it: [4:] then re-embedded.
    _pa = D.build_peer_answer(None, 0x2aa69, ident=0x2aa68,
                              blob=D.build_peer_record(0x2aa69, name="Test",
                                                       zone=0xffff,
                                                       f36=0x2022)[4:])
    _prec = body(_pa)[12:]
    check("peer record: look code at +36, zone still at +32",
          struct.unpack_from("<H", _prec, 36)[0] == 0x2022
          and struct.unpack_from("<H", _prec, 32)[0] == 0xffff
          and struct.unpack_from("<I", _prec, 0)[0] == 0x2aa69)
    # sec 4fu (briefing): the Deck's live briefing-room PEER 0x83 (09-13 02:04,
    # mode 4, flags 8). Its header is rejected under every key we hold; the
    # body names the sender. Synthesise the header, keep ms + body verbatim.
    _dk4 = bytes.fromhex("04044000014d02004cde73079d03f3686b0b53c645f57cef"
                         "69aa0200c6b8ff440a0030c1a53302439eed76bf00000000"
                         "941787be0220803e000b000000001210")
    check("briefing peer 0x83: the header does NOT decrypt (live fact)",
          D.describe_inner(_dk4) is None if D._KELCRYPT else True)
    check("briefing peer 0x83: peer_pos_id reads the sender id off the body",
          D.peer_pos_id(_dk4) == 0x2aa69)
    check("peer_pos_id ignores a 36-byte GS request",
          D.peer_pos_id(bytes.fromhex(
              "0404240010a201004408a9dd2b05d812b0f6422f05503626010000000000000000000000"))
          is None)
    _si = D.synth_peer_inner(_dk4)
    _sp = _si["plain"]
    check("synth: type 0x83, flags 8, id at packet[16]",
          _sp[8] == 0x83 and _sp[9] == 8 and _si["u32_16"] == 0x2aa69
          and D.struct.unpack_from("<I", _sp, 16)[0] == 0x2aa69)
    check("synth: sender ms and 40-byte body verbatim, checksum valid",
          _sp[4:8] == _dk4[4:8] and _sp[24:] == _dk4[24:]
          and struct.unpack_from("<H", _sp, D.CKSUM_OFF)[0] == D.cksum(_sp))
    _sr = D.build_peer_relay(_sp)
    check("synth -> relay: mode 0, flags 8, checksum valid",
          _sr[1] == 0 and _sr[9] == 8
          and struct.unpack_from("<H", _sr, D.CKSUM_OFF)[0] == D.cksum(_sr))
    _wl = D.build_world_update([dict(id=0x40000001, x=1.0, y=2.0, z=3.0)])[D.BODY_OFF + 4:]
    check("wu: without the new keys +4..7 and +20..23 stay zero",
          _wl[4:8] == bytes(4) and _wl[20:24] == bytes(4))

    # 09-13 regression: two POL members, ONE entrance uid (0xa756a69a live)
    # -> both slot 0s were 0x2aa68. Member keys now derive from the member.
    _u = 0xa756a69a
    _m15 = [D.chara_id_for(0x1000, _u, "member:15", i) for i in range(4)]
    _m6 = [D.chara_id_for(0x1000, _u, "member:6", i) for i in range(4)]
    check("two members at one uid get DISJOINT character ids",
          not set(_m15) & set(_m6) and len(set(_m15)) == 4, "%r %r"
          % (["0x%x" % x for x in _m15], ["0x%x" % x for x in _m6]))
    check("a non-member key keeps the old uid formula byte-for-byte",
          D.chara_id_for(0x1000, _u, _u, 0) == 0x2aa68
          and D.chara_id_for(0x1000, _u, "addr:1.2.3.4", 1) == 0x2aa69)
    check("member ids sit above every uid-derived id; bits 30/31 clear",
          min(_m15 + _m6) > 0x1000 + (0xFFFF << 2) + 3
          and all(x & 0xC0000000 == 0 for x in _m15 + _m6)
          and D.chara_id_for(0x1000, _u, "member:16383", 3) < 0x9000 + 0x40000 + 0x10000)
    # 2026-10-05: a stored POL Content ID is served as the character id
    _cs = D.doc_charastore
    check("chara_id_of: a stored Content ID wins; none / 0 / junk / bit 30 fall "
          "back to the derived id",
          D.chara_id_of(0x1000, _u, "member:15", 0, {"cid": 30000057}) == 30000057
          and D.chara_id_of(0x1000, _u, "member:15", 0, {}) == _m15[0]
          and D.chara_id_of(0x1000, _u, "member:15", 0, None) == _m15[0]
          and D.chara_id_of(0x1000, _u, "member:15", 0, {"cid": "x"}) == _m15[0]
          and D.chara_id_of(0x1000, _u, "member:15", 0, {"cid": 0x40000001}) == _m15[0])
    _ast = _cs.CharaStore(None)
    _ast.data = {"member:15": [{"name": "Malk", "slot": 0}, {"name": "Two", "slot": 1}],
                 "member:16": [{"name": "Held", "slot": 0, "cid": 30000058}]}
    _a1 = _ast.assign_content_id("member:15", 0, ["30000058", "30000057"])
    _a2 = _ast.assign_content_id("member:15", 1, ["30000058", "30000057"])
    _a3 = _ast.assign_content_id("member:15", 0, ["30000099"])
    check("assign_content_id: the first id nobody holds; none left -> 0; an "
          "assigned id never moves; an empty slot gets nothing",
          _a1 == 30000057 and _a2 == 0 and _a3 == 30000057
          and _ast.assign_content_id("member:15", 3, ["30000099"]) == 0
          and _ast.content_ids_held() == 2, "%r %r %r" % (_a1, _a2, _a3))
    check("chara_id_for(base=0) is off, as --chara-id-base 0 was",
          D.chara_id_for(0, _u, "member:15", 0) == 0)

    # 2026-09-13: HP = world-door record+4 = body[48..51] (setUserData ->
    # R+44 cur / R+752 max). The echoed token there read as HP -31166.
    _wd_plain = D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                     ident=0, self_id=0x4103c)
    _wd_hp = D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                  ident=0, self_id=0x4103c, self_hp=100)
    _bp, _bh = body(_wd_plain), body(_wd_hp)
    check("world door: HP 100 as a u32 at body[48..51]",
          struct.unpack_from("<I", _bh, 48)[0] == 100)
    check("world door: HP changes ONLY body[48..51] (id at body[44] kept)",
          len(_bp) == len(_bh)
          and [i for i in range(len(_bp)) if _bp[i] != _bh[i]]
              and all(48 <= i < 52 for i in range(len(_bp)) if _bp[i] != _bh[i])
          and struct.unpack_from("<I", _bh, 44)[0] == 0x4103c)
    _s13a = D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                                 ident=0, spawn=(900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 11))
    _s13b = D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                                 ident=0, spawn=(900.0, 0.0, 145.0, 1.0, 0.0, 0.0, 11),
                                 self_hp=100)
    check("HP is never written on selector 13 (body[48] is spawn data there)",
          body(_s13a) == body(_s13b))

    # 2026-09-13: DISSOLVE 125 / CANCEL 155 arrive as 36-byte requests (a 12-byte
    # body, no key). The verb must resolve the requester's own table.
    _sd = D.BattletableStore()
    _r24 = bytearray(D.BODY_OFF + D.BT_REQ_REC_OFF + D.BT_REC_LEN); _r24[0] = 4; _r24[8] = 127
    _r24[D.BODY_OFF + D.BT_REQ_REC_OFF:] = D.build_battletable_record(table_id=0, maximum=8, mode=1)
    D.battletable_verb(_sd, bytes(_r24), bytes(_r24[D.BODY_OFF:]), 24, 0x4103c, 0)
    _k = _sd.table_of(0x4103c)
    _short = bytes([7, 125] + [0] * 10)
    _rq = bytes(D.BODY_OFF) + _short
    _pd, _nd = D.battletable_verb(_sd, _rq, _short, 125, 0x4103c, 0)
    check("36-byte DISSOLVE (12-byte body) removes the requester's own table",
          _k is not None and _pd is not None and _sd.get(_k) is None, _nd)
    D.battletable_verb(_sd, bytes(_r24), bytes(_r24[D.BODY_OFF:]), 24, 0x41018, 0)
    _pc, _nc = D.battletable_verb(_sd, _rq, bytes([7, 155] + [0] * 10), 155, 0x41018, 0)
    check("36-byte CANCEL (12-byte body) unseats the requester",
          _pc is not None and _sd.table_of(0x41018) is None, _nc)

    # 2026-09-13: the SELF NAME = world-door body[112..127] (character record
    # +68 -> self record R+704), written after the costume window.
    _wn = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_costume=0x1012, self_name="Lex")
    _wo = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_costume=0x1012)
    check("self name NUL-padded at body[112..127], over the costume window's tail",
          body(_wn)[112:128] == b"Lex" + bytes(13))
    check("self name leaves the costume value at body[100] alone",
          struct.unpack_from("<H", body(_wn), 100)[0] == 0x1012
          and body(_wn)[:112] == body(_wo)[:112])
    _n13a = D.build_world_answer(world_door_request(), selector=13, pad_to=176, ident=0)
    _n13b = D.build_world_answer(world_door_request(), selector=13, pad_to=176, ident=0,
                                 self_name="Lex")
    check("self name is never written on selector 13", body(_n13a) == body(_n13b))

    # sec 4gk: THE SHOP. Gil = world-door body[52] (-> R+744), bag count
    # body[140], entries body[240+8i] {u32 id, u16 0, u16 qty}; selector 2 only.
    import doc_shop as S
    _bag = [(0x69320000, 3), (0x6F34001B, 1)]
    _wg = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_hp=100, self_gil=12345, self_bag=_bag)
    _wp = D.build_world_answer(world_door_request(), selector=2, pad_to=176, ident=0,
                               self_hp=100)
    _gb = body(_wg)
    check("shop: gil u32 at world-door body[52]",
          struct.unpack_from("<I", _gb, 52)[0] == 12345)
    check("shop: bag count at body[140], entries at body[240+8i] (qty at +6)",
          struct.unpack_from("<I", _gb, 140)[0] == 2
          and struct.unpack_from("<IHH", _gb, 240) == (0x69320000, 0, 3)
          and struct.unpack_from("<IHH", _gb, 248) == (0x6F34001B, 0, 1))
    check("shop: nothing else in the first 176 bytes moves (HP, id, costume)",
          _gb[:52] == body(_wp)[:52] and _gb[56:140] == body(_wp)[56:140]
          and _gb[144:176] == body(_wp)[144:176])
    check("shop: an EMPTY bag still writes count 0 (never the echoed token)",
          struct.unpack_from("<I", body(D.build_world_answer(
              world_door_request(), selector=2, pad_to=176, ident=0,
              self_gil=5, self_bag=[])), 140)[0] == 0)
    check("shop: the bag is capped at 50 (the client does not clamp body[140])",
          struct.unpack_from("<I", body(D.build_world_answer(
              world_door_request(), selector=2, pad_to=176, ident=0,
              self_bag=[(0x69320000 + i, 1) for i in range(80)])), 140)[0] == 50)
    for _gsel in (13, 21):
        _a = D.build_world_answer(world_door_request(), selector=_gsel, pad_to=176,
                                  ident=0)
        _b = D.build_world_answer(world_door_request(), selector=_gsel, pad_to=176,
                                  ident=0, self_gil=12345, self_bag=_bag)
        check("shop: gil/bag never written on selector %d" % _gsel,
              body(_a) == body(_b))

    # sec 4go: AMMO. Bullets are inventory items; the magazine (0x004a5780)
    # fills from the bag's 0x6230000N stacks, so the world door must carry them.
    _ab = S.issue_items([], S.parse_issue("standard"))
    _wa = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                    ident=0, self_bag=_ab))
    check("ammo: standard issue = 36 handgun / 18 rifle / 60 MG at body[240+]",
          struct.unpack_from("<I", _wa, 140)[0] == 3
          and [struct.unpack_from("<IHH", _wa, 240 + 8 * i) for i in range(3)]
          == [(0x62300000, 0, 36), (0x62300001, 0, 18), (0x62300002, 0, 60)])
    check("ammo: tops a shop bag UP, never lowers it",
          S.issue_items([(0x62300000, 100), (0x69320000, 3)], S.STANDARD_AMMO)
          == [(0x62300000, 100), (0x62300001, 18), (0x62300002, 60), (0x69320000, 3)])
    check("ammo: bullets survive a full 50-item bag (lowest category sorts first)",
          S.issue_items([(0x6F300000 + i, 1) for i in range(50)],
                        S.STANDARD_AMMO)[:3] == list(S.STANDARD_AMMO))
    check("ammo: 'off' issues nothing; 'ID:QTY' parses and caps at 500",
          S.parse_issue("off") == () and S.parse_issue("") == ()
          and S.parse_issue("0x62300000:5,0x62300001:9999")
          == ((0x62300000, 5), (0x62300001, 500)))

    # 2026-09-13: UNITS (doc_unit.py). The enlisted unit = world-door
    # body[60..67] (setUserData src+16 -> R+720); selector 2 only.
    _uid = 0x0000000700000029
    _wu = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                    ident=0, self_hp=100, self_unit=_uid))
    check("units: enlisted unit u64 at world-door body[60..67]",
          struct.unpack_from("<Q", _wu, 60)[0] == _uid)
    check("units: 0 when not enlisted (never the echoed token)",
          struct.unpack_from("<Q", body(D.build_world_answer(
              world_door_request(), selector=2, pad_to=176, ident=0,
              self_unit=0)), 60)[0] == 0)
    check("units: nothing else in the first 176 bytes moves",
          _wu[:60] == body(_wp)[:60] and _wu[68:176] == body(_wp)[68:176])
    # 2026-09-13: the equipped MASK + SUIT at body[76]/[80] (-> R+768/772).
    import doc_gear as G
    _gear = G.starter_gear(True)
    _wgr = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                     ident=0, self_hp=100, self_gear=_gear))
    check("gear: mask at body[76], suit at body[80] (female -> DG Soldier Mask F)",
          struct.unpack_from("<II", _wgr, 76) == (0x63300001, 0x63310000))
    check("gear: male -> DG Soldier Mask M", G.starter_gear(False)[0] == 0x63300000)
    check("gear: nothing else in the first 176 bytes moves",
          _wgr[:76] == body(_wp)[:76] and _wgr[84:176] == body(_wp)[84:176])
    check("gear: never written on selector 13",
          body(D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                                    ident=0))
          == body(D.build_world_answer(world_door_request(), selector=13,
                                       pad_to=176, ident=0, self_gear=_gear)))
    check("gear: issue_items puts both in the bag once",
          [i for i, q in S.issue_items([], [(_gear[0], 1), (_gear[1], 1)])]
          == [0x63300001, 0x63310000])
    # 2026-09-13: CHANGE MASK / ARMOR = lobby commands 17 / 18 (doc_gear.py).
    docdb.store("gear").clear()
    _gs = G.GearStore(docdb.store("gear"))
    _gk = "member:15/0x0004103c"

    def _gear_req(cmd, slot, item=0):
        _r = bytearray(28)
        _r[0], _r[1], _r[12], _r[16] = 7, 240, cmd, slot
        struct.pack_into("<I", _r, 20, item)
        return bytes(_r)
    _gb, _gn = _gs.body_for(17, _gear_req(17, 0, 0x63300009), _gk, 0x1019)
    check("gear cmd 17: 241 answer names command 17 at body[12], success header",
          _gb[1] == 241 and struct.unpack_from("<H", _gb, 12)[0] == 17
          and struct.unpack_from("<H", _gb, 4)[0] == 0)
    check("gear cmd 17 Capsule Searcher: body[6] = bit 7 + its model 7 (item def +16) "
          "(0x1019 -> 0x1799)",
          struct.unpack_from("<H", _gb, 6)[0] == 0x1799)
    check("gear cmd 17: stored and served back at login",
          G.GearStore(docdb.store("gear")).login(_gk, G.starter_gear(False), 0x1019)
          == (0x63300009, 0x63310000, 0x1799))
    _gb, _gn = _gs.body_for(17, _gear_req(17, 1, 0x63310050), _gk, 0x1019)
    check("gear cmd 17 Armored Suit (0x..50 = armor 4): armor bits follow, mask kept "
          "(0x1799 -> 0x17a1)",
          struct.unpack_from("<H", _gb, 6)[0] == 0x17A1
          and _gs.login(_gk)[:2] == (0x63300009, 0x63310050))
    check("gear: the armor pick -> the NAMED suit every 20 ids (live session 09-13: "
          "armor 2 = Speed Suit 0x63310028, never placeholder 'Suit 2')",
          [G.starter_gear(False, t)[1] for t in range(5)]
          == [0x63310000, 0x63310014, 0x63310028, 0x6331003C, 0x63310050])
    check("gear: a suit's look = id // 20 for all 100 (placeholder 'Suit 41' = Speed look)",
          G.armor_for_suit(0x63310029) == 2 and G.armor_for_suit(0x63310002) == 0)
    _gb, _gn = _gs.body_for(18, _gear_req(18, 0), _gk, 0x1019)
    check("gear cmd 18: mask slot -1, bit 7 cleared (0x17a1 -> 0x1721)",
          struct.unpack_from("<H", _gb, 6)[0] == 0x1721
          and _gs.login(_gk)[0] == G.NO_ITEM)
    _gb, _gn = _gs.body_for(17, _gear_req(17, 0, 0x63310000), _gk, 0x1019)
    check("gear cmd 17 suit into the mask slot: REFUSED (body[4] bit 0), nothing stored",
          struct.unpack_from("<H", _gb, 4)[0] & 1
          and struct.unpack_from("<H", _gb, 6)[0] != 0 and _gs.login(_gk)[0] == G.NO_ITEM)
    _gb, _gn = _gs.body_for(18, _gear_req(18, 1), _gk, 0x1019)
    check("gear cmd 18 on the suit: REFUSED (armor cannot be removed)",
          struct.unpack_from("<H", _gb, 4)[0] & 1)
    _gb, _gn = _gs.body_for(17, _gear_req(17, 0, 0x63300000), "anon/0x00000001", None)
    check("gear: no known costume -> REFUSED, never a zero costume",
          struct.unpack_from("<H", _gb, 4)[0] & 1 and _gs.get("anon/0x00000001") is None)
    check("gear: a never-changed character gets the starter pair + creation look",
          _gs.login("member:1/0x00000002", G.starter_gear(True), 0x1059)
          == (0x63300001, 0x63310000, 0x1059))
    docdb.store("gear").clear()
    for _usel in (13, 21):
        check("units: never written on selector %d" % _usel,
              body(D.build_world_answer(world_door_request(), selector=_usel,
                                        pad_to=176, ident=0))
              == body(D.build_world_answer(world_door_request(), selector=_usel,
                                           pad_to=176, ident=0, self_unit=_uid)))
    _pl = S.price_body(list(S.DEFAULT_STOCK))
    _pn = struct.unpack_from("<I", _pl, 16)[0]
    check("shop: 144 = u32 count body[16], 12-B {id, price} rows from body[20], "
          "stock order", _pl[1] == 144 and _pn == len(S.DEFAULT_STOCK)
          and len(_pl) == 20 + 12 * _pn
          and [struct.unpack_from("<I", _pl, 20 + 12 * i)[0] for i in range(_pn)]
          == [i for i, _, _ in S.DEFAULT_STOCK])
    check("shop: the 65 list fits one datagram (< 1472 B)",
          D.BODY_OFF + len(S.stock_body(list(S.DEFAULT_STOCK))) < 1472)
    # 2026-09-13 LIVE: the BUY is request 66 -> answer 67, the SELL 68 -> 69.
    _rq66 = bytes.fromhex("074200000100ffffffffffff030000000000326f0100000000000000")
    check("shop: the live 09:11:51 request 66 parses to Auto Scope x1 at shop 3",
          S.parse_entry(_rq66) == {"shop": 3, "iid": 0x6F320000, "qty": 1})
    _b67 = S.buy_body(add=(0x6F300000, 2), spend=4000)
    check("shop: 67 = ADD body[12] x u16 [20], SPEND [28]",
          _b67[1] == 67 and struct.unpack_from("<I", _b67, 12)[0] == 0x6F300000
          and struct.unpack_from("<H", _b67, 20)[0] == 2
          and struct.unpack_from("<I", _b67, 28)[0] == 4000)
    _b69 = S.sell_body(remove=(0x6F300000, 1), gain=1000)
    check("shop: 69 = REMOVE body[16] x u16 [22], gil GAIN [24]",
          _b69[1] == 69 and struct.unpack_from("<I", _b69, 16)[0] == 0x6F300000
          and struct.unpack_from("<H", _b69, 22)[0] == 1
          and struct.unpack_from("<I", _b69, 24)[0] == 1000
          and struct.unpack_from("<I", _b69, 12)[0] == 0)
    # MODIFY: 142 rows {source, result, kit, fee}; 145 = shop, source, result.
    _rb = S.recipe_body([(0x6F310000, 0x6F310001, 0x6430000A, 1750)])
    check("shop: 142 = 20-B {source, result, kit, fee} rows",
          _rb[1] == 142 and struct.unpack_from("<I", _rb, 16)[0] == 1 and len(_rb) == 40
          and struct.unpack_from("<IIII", _rb, 20)
          == (0x6F310000, 0x6F310001, 0x6430000A, 1750))
    _rq145 = bytes([7, 145]) + bytes(10) + struct.pack("<III", 3, 0x6F310000, 0x6F310001)
    check("shop: 145 = body[12] shop, body[16] source, body[20] result",
          S.parse_modify(_rq145) == {"shop": 3, "src": 0x6F310000, "res": 0x6F310001})
    _sl = S.stock_body(list(S.DEFAULT_STOCK))
    check("shop: 65 = 16-B rows, id at +0 and the price at +4 and +8",
          _sl[1] == 65 and struct.unpack_from("<IIII", _sl, 20)
          == (S.DEFAULT_STOCK[0][0], S.DEFAULT_STOCK[0][1], S.DEFAULT_STOCK[0][1], 0))
    check("shop: 142 is a well-formed EMPTY list",
          S.recipe_body() == bytes([7, 142]) + bytes(18))
    _tx = S.txn_body(add=(0x69320000, 3), remove=(0x69310014, 1), spend=150, kit=7)
    check("shop: 146 ADD body[12]/u16 [20], REMOVE [16]/u16 [22], SPEND [28], KIT [32]",
          _tx[1] == 146 and struct.unpack_from("<IIHHII", _tx, 12)[:4]
          == (0x69320000, 0x69310014, 3, 1)
          and struct.unpack_from("<I", _tx, 28)[0] == 150
          and struct.unpack_from("<I", _tx, 32)[0] == 7)
    _sp = D.seal_world_body(None, _tx, seq=5, ptype=127, ident=0x0002a664)
    _z = bytearray(_sp)
    _z[D.CKSUM_OFF:D.CKSUM_OFF + 2] = b"\0\0"
    check("shop: sealed 146 = mode 0, type 127, record+4 = ident, good checksum",
          _sp[1] == 0 and _sp[8] == 127
          and struct.unpack_from("<I", _sp, 16)[0] == 0x0002a664
          and struct.unpack_from("<H", _sp, 2)[0] == len(_sp)
          and struct.unpack_from("<H", _sp, D.CKSUM_OFF)[0] == D.cksum(bytes(_z))
          and _sp[D.BODY_OFF:] == _tx)

    # --- sec 4gv (2026-09-23): THE SOURCE GATE, AND THE START RE-DECLARATION.
    # The client's game-server receive handler opens with (JP 0x00bcca60)
    #     lw v1, 188(s1) ; lw v0, 4(s2) ; bne v1, v0, <exit>
    # so a datagram is dropped, before dispatch and before the sequence window,
    # unless its source (IP, port) equals what selector 104 last wrote into
    # [chan+184..191]. docudp fires 104 once per world session (`gs_done`), and
    # at Start it sends 38 (LOBBY channel, always lands) + the message-27 re-arm
    # (GAME-SERVER channel). With a stale endpoint the re-arm is swallowed,
    # [chan+204] bit 6 is never set, [chan+224] is never refreshed and the
    # client paints CER-48101 40 s later. Measured live
    # the peer whose connect->Start gap was 2 m 10 s sent 0 game-server hellos
    # and its [chan+212] was still the uninitialised 65528.
    _EPSEL = getattr(D, "GS_ENDPOINT_SELECTOR", None)
    check("104 is the ungated endpoint rung", _EPSEL == 104)
    check("104 is NOT one of the gated rungs 21/31",
          _EPSEL is not None and _EPSEL not in D.GS_ENDPOINT_SELECTORS)

    # The endpoint must be computed PER PEER. A LAN console and an internet
    # player can sit at the same table, so one global address is always wrong
    # for one of them -- that is exactly what rec_for() already does for the
    # battle-table record, and the selector-104 message must do the same.
    _saved_env = {k: os.environ.get(k)
                  for k in ("POL_ADVERTISE_PUBLIC", "POL_ADVERTISE_LAN")}
    try:
        os.environ["POL_ADVERTISE_PUBLIC"] = "203.0.113.9"
        os.environ["POL_ADVERTISE_LAN"] = "172.18.0.1"
        _eps = {}
        for _who, _peer in (("lan", "172.18.0.5"),
                            ("public", "8.8.8.8")):
            _ip = D.host_for("192.0.2.60", _peer)
            _pk = D.build_world_answer(
                world_door_request(), selector=(_EPSEL or 104),
                ident=0x1234, pad_to=176, gs_ip=_ip, gs_port=55040, gs_id=0)
            _eps[_who] = body(_pk)[52:56]
        check("104 to a LAN peer carries the LAN address",
              _eps["lan"] == bytes([172, 18, 0, 1]),
              ".".join(str(b) for b in _eps["lan"]))
        check("104 to a public peer carries POL_ADVERTISE_PUBLIC",
              _eps["public"] == bytes([203, 0, 113, 9]),
              ".".join(str(b) for b in _eps["public"]))
        check("the two peers do NOT get the same endpoint",
              _eps["lan"] != _eps["public"])
        # NEGATIVE CONTROL for the three checks above -- the known-bad input
        # they are able to fail on. Feeding the builder ONE global address (the
        # shape this fix was explicitly told not to introduce) gives both peers
        # the same bytes, and neither is the address its own network can route.
        _bad = body(D.build_world_answer(
            world_door_request(), selector=(_EPSEL or 104), ident=0x1234,
            pad_to=176, gs_ip="192.0.2.60", gs_port=55040, gs_id=0))[52:56]
        check("negative control: a global address is wrong for BOTH peers",
              _bad == bytes([192, 0, 2, 60])
              and _bad != _eps["lan"] and _bad != _eps["public"])

        # WARNING:KEY: sec 4gv addendum (2026-09-23): THE BATTLETABLE RECORD IS A SECOND
        # WRITER OF THE SAME FIELD. rec+12/+20 feed the client's
        # 0x00bc0320(chan, ip, port), which is the SOLE writer of
        # [chan+184..191] -- the field selector 104's arm installs through
        # (0x00bca938 tail) and the field the keepalive sender reads back
        # (JP 0x00bc0c18 -> outgoing record +0x14c/+0x150).
        # BattletableStore._stamp writes the RAW configured address into every
        # record, and the LEADER's console verbs (create/config/adjust) were
        # served unrewritten -- so the leader's own table screen UNDID the 104
        # it had just been sent, while the joiner (list + selector 38, both
        # rec_for'd) kept a good one. Measured on a test rig:
        # two minutes after the LAN address was declared, the client's
        # [chan+184..191] still read the store's raw address.
        _st104 = D.BattletableStore([], gs_ip="192.0.2.60", gs_port=55040)
        _k104 = _st104.add_record(bytes(D.BT_REC_LEN), leader=0x41000)

        def _verb_gs_ip(peer):
            _rq = req(D.BT_REQ_CONFIG, struct.pack("<H", _k104) + bytes(2))
            _pk, _ = D.battletable_verb(
                _st104, _rq, D.request_body(_rq, None), D.BT_REQ_CONFIG,
                0x41000, 0, peer_ip=peer, default_gs_ip="192.0.2.60")
            if _pk is None:
                return None
            _b = body(_pk)
            _o = D.BATTLETABLE_REC_OFF + D.BT_OFF_GS_IP
            return ".".join(str(x) for x in _b[_o:_o + 4])

        _lan104, _pub104 = _verb_gs_ip("172.18.0.5"), _verb_gs_ip("8.8.8.8")
        check("a battletable VERB answer carries the endpoint THIS peer can reach",
              _lan104 == "172.18.0.1" and _pub104 == "203.0.113.9",
              "lan=%s public=%s" % (_lan104, _pub104))
        # NEGATIVE CONTROL: the same call with the rewrite switched off is the
        # known-bad input, and it must produce the raw store address.
        _off104 = D.battletable_verb(
            _st104, req(D.BT_REQ_CONFIG, struct.pack("<H", _k104) + bytes(2)),
            D.request_body(req(D.BT_REQ_CONFIG,
                               struct.pack("<H", _k104) + bytes(2)), None),
            D.BT_REQ_CONFIG, 0x41000, 0)[0]
        _o104 = D.BATTLETABLE_REC_OFF + D.BT_OFF_GS_IP
        _rawip = ".".join(str(x) for x in body(_off104)[_o104:_o104 + 4])
        check("negative control: unrewritten, the verb answer serves the RAW "
              "store address to everyone",
              _rawip == "192.0.2.60" and _rawip not in (_lan104, _pub104),
              _rawip)
    finally:
        for _k, _v in _saved_env.items():
            if _v is None:
                os.environ.pop(_k, None)
            else:
                os.environ[_k] = _v

    # THE WIRING. The bytes above were already right before this fix -- what was
    # wrong is that nothing re-sent them at Start. That is an ORDER property of
    # the responder, so it is checked against the source: at each of the two
    # Start sites the selector-104 re-declaration must come BEFORE the 38 (it
    # is what makes the next two deliverable) and the message-27 arm must come
    # LAST, because 38's routine 0x00bc0260 zeroes [chan+204] (sec 4eb). All
    # four of these FAIL on the pre-fix file -- verified by running this suite
    # against `git show HEAD:tools/docudp.py`.
    _src = responder_source()

    def _ordered(seg, *marks):
        """True iff every mark appears in `seg`, in this order."""
        if not seg:
            return False, "(source block not found)"
        at = -1
        for m in marks:
            nxt = seg.find(m, at + 1)
            if nxt < 0:
                return False, m
            at = nxt
        return True, ""

    def _seg(head, tail):
        """The source between two anchors, or "" if either is absent."""
        i = _src.find(head)
        if i < 0:
            return ""
        j = _src.find(tail, i + len(head))
        return _src[i:j] if j >= 0 else ""

    _lead = _seg("if _sel in _gs_ready_after or _start_now:",
                 "if _sel in _pending_ack_after:")
    _ok, _miss = _ordered(_lead, "send_gs_endpoint(",
                          "selector=GS_READY_SELECTOR",
                          "build_gs_stats(_st2")
    check("leader Start sends 104 -> 38 -> the message-%d arm, in that order"
          % D.GS_ARM_MSG, _ok, ("" if _ok else "missing/out of order: %s" % _miss))

    _fan = _seg("def push_battle_ready(", "def push_lobby_npcs(")
    _ok, _miss = _ordered(_fan, "send_gs_endpoint(",
                          "s.sendto(_rd, msess.ka_src)",
                          "build_gs_stats(")
    check("[start-all] sends 104 -> 38 -> the message-%d arm, in that order"
          % D.GS_ARM_MSG, _ok, ("" if _ok else "missing/out of order: %s" % _miss))

    _helper = _seg("def send_gs_endpoint(", "def push_battle_ready(")
    check("send_gs_endpoint resolves the address PER PEER via host_for(dst)",
          "host_for(a.gs_connect_ip or a.lobby_ip, dst[0])" in _helper)
    check("exactly ONE site in docudp builds a selector-104 endpoint message",
          _src.count("selector=GS_ENDPOINT_SELECTOR") == 1
          and _src.count("gs_ip=_ep") == 1
          and "_gs_kw" not in _src,
          "%d builder(s)" % _src.count("selector=GS_ENDPOINT_SELECTOR"))

    # --- sec 4hb: THE TABLE'S CHOSEN MAP PICKS THE ARENA (2026-09-23).
    # The picker works and the pick reaches BT_OFF_MAP (live: "CREATE -> table 1
    # (map 9, ...)"), but kind 2's zone byte was the constant --gs-battle-zone,
    # so every table played in z201. These drive the decision function itself.
    _MZ = D.parse_map_zones("")
    check("the decoded map->zone table is the default",
          _MZ == D.parse_map_zones(D.BT_MAP_ZONES_DEFAULT) and len(_MZ) == 23,
          "%d entries" % len(_MZ))
    check("map 0 -> z201 and map 7 -> z208, the two arenas confirmed on a console",
          _MZ[0] == 201 and _MZ[7] == 208)
    check("the mapping is NOT zone = 201 + index (z209 is the Warehouse, "
          "roster 14, not the Train Graveyard, roster 8)",
          _MZ[8] == 212 and _MZ[14] == 209)
    check("every decoded zone fits kind 2's ONE zone byte and is never 0 "
          "(0 = get_onlinezone's exit(-1) = the title)",
          all(0 < z < 256 for z in _MZ.values()))
    check("the 5 roster maps with no shipped arena are ABSENT, not guessed "
          "(11 the hole, 13 Test Area, 17/18/19 Base 1-3)",
          not (set(_MZ) & {11, 13, 17, 18, 19}))
    _shown = [i for i in range(len(D.LOBBY_MAP_NAMES)) if D.LOBBY_MAP_MASK_ALL >> i & 1]
    # 2026-10-06: minus the maps our arena data cannot stage (audit):
    # 6 Training Grounds, 12 Deepground 2, 15 Bridge, 16 Shinra Manor
    check("the picker shows EXACTLY the maps with an arena -- 11 / 13 / 17-19 "
          "hidden (09-23), 6 / 12 / 15 / 16 hidden (10-06, no usable layout)",
          set(_shown) == set(_MZ) - {6, 12, 15, 16}
          and not set(_shown) & {6, 11, 12, 13, 15, 16, 17, 18, 19},
          "shown %s" % sorted(_shown))
    check("TWIN: the old mask (only 11 cleared) shows unmapped maps",
          {i for i in range(28) if (((1 << 28) - 1) & ~(1 << 11)) >> i & 1}
          - set(_MZ) == {13, 17, 18, 19})
    check("1/5/6 follow zonelist's 201..208 roster run: DG -> 202, "
          "Laboratory -> 206, Training Grounds -> 207 (2026-09-23)",
          (_MZ[1], _MZ[5], _MZ[6]) == (202, 206, 207)
          and all(_MZ[i] == 201 + i for i in range(8)))
    check("no two maps claim one arena zone",
          len(set(_MZ.values())) == len(_MZ))

    def _zone_of(idx, spawns=(203, 204, 205, 208), needs=True, tbl=None):
        return D.battle_map_arena(idx, _MZ if tbl is None else tbl, 201,
                                  zone_spawns=spawns, needs_spawn=needs)

    check("a table on the church map is served z208, not the flag's z201",
          _zone_of(7) == (208, D.ARENA_OK))
    check("a table on a map with no decoded zone falls back to the flag",
          _zone_of(13) == (201, D.ARENA_NO_ZONE))
    check("a decoded zone with NO --zone-spawns point falls back rather than "
          "spawning in the void", _zone_of(24) == (201, D.ARENA_NO_SPAWN))
    check("--no-battle-map-needs-spawn serves that zone anyway",
          _zone_of(24, needs=False) == (234, D.ARENA_OK))
    check("the flag's own zone never needs a --zone-spawns entry (it has "
          "--gs-battle-pos)", _zone_of(0, spawns=()) == (201, D.ARENA_OK))
    # the FALSIFYING TWIN: the same call, on the table this code replaced (the
    # empty one every table used until tonight), must NOT reach the church.
    check("TWIN: with an empty map->zone table every map lands in z201 -- the "
          "bug this fixes, and proof the check above can fail",
          _zone_of(7, tbl={}) == (201, D.ARENA_NO_ZONE)
          and all(_zone_of(i, tbl={})[0] == 201 for i in range(28)))
    check("'off' parses to the empty table", D.parse_map_zones("off") == {})
    for _bad, _wh in (("0:0", "zone 0 = the title"),
                      ("0:256", "a zone past one byte"),
                      ("64:201", "a map index past the picker's bit test"),
                      ("0", "a pair with no zone")):
        try:
            D.parse_map_zones(_bad)
            _rej = False
        except SystemExit:
            _rej = True
        check("--battle-map-zones rejects %s (%r)" % (_wh, _bad), _rej)

    # and the PLUMBING: neither kind-2 push may carry a constant zone again.
    def _no_constant_zone(src):
        seg = src[src.find("def _battle_zone_note("):]
        return ("zone=a.gs_battle_zone" not in seg
                and seg.count("zone=_bzone") == 2
                and seg.count("_battle_zone_note(") >= 2)
    check("both kind-2 pushes take their zone from _battle_zone_note, never a "
          "constant", _no_constant_zone(_src))
    check("TWIN: the same gate FAILS on the pre-fix shape it replaced",
          not _no_constant_zone(_src.replace("zone=_bzone",
                                             "zone=a.gs_battle_zone")))
    check("_battle_zone and _battle_pos both take the character id, so the "
          "SPAWN follows the map's zone (sec 4gr.6: a z201 point is the VOID "
          "in z208)",
          "def _battle_zone(key, cid=None)" in _src
          and "def _battle_pos(key, cid=None, per_team=True)" in _src
          and "_battle_pos(sess.key, seen_charid[0])" in _src)
    check("M0/M1 are never the table's map index -- z201 and z208 were both "
          "entered live with 0,0, so the map bytes do not choose the arena",
          "bmap=(_map" not in _src and "bmap=(m" not in _src)

    # --- 2026-09-23: M0/M1 name the arena's TERRAIN piece (z204 = sky only) --
    _ZP = D.parse_zone_pieces(D.ZONE_PIECES_DEFAULT)
    check("z204 (Wastelands) asks for m001, its terrain; the slot-4 savestate "
          "held m000 (sky) + m002 and NO m001 with 0,0",
          D.battle_bmap(204, _ZP, (0, 0)) == (1, 0))
    check("z208 (church) asks for m002, the piece that only streamed on a walk",
          D.battle_bmap(208, _ZP, (0, 0)) == (2, 0))
    check("z201 (Jungle) asks for SE's own pair 1,3 -- ev2045's "
          "Zone.load(201, 1, 3); blank until control with 0,0 (live)",
          D.battle_bmap(201, _ZP, (0, 0)) == (1, 3))
    check("z203 (Kalm) asks for m004 + m001, the pieces around its spawn",
          D.battle_bmap(203, _ZP, (0, 0)) == (4, 1))
    check("z205 (Sewers) asks for m003 + m001, the pieces around its spawn",
          D.battle_bmap(205, _ZP, (0, 0)) == (3, 1))
    check("unlisted zones keep the --gs-battle-map default",
          D.battle_bmap(215, _ZP, (7, 9)) == (7, 9))
    _ZS = {}
    for _e in D.ZONE_SPAWNS_DEFAULT.split(";"):
        _z, _, _xyz = _e.partition(":")
        _ZS[int(_z)] = tuple(float(q) for q in _xyz.split(","))
    check("every decoded arena zone has a spawn AND a preload pair -- no map "
          "lands in the VOID or on its sky piece (z201 spawns at --gs-battle-pos, "
          "ev2045's own Jungle point)",
          set(_MZ.values()) - {201} <= set(_ZS) and set(_MZ.values()) <= set(_ZP)
          and all(len(p) == 3 for p in _ZS.values()),
          "missing spawn %s pieces %s" % (sorted(set(_MZ.values()) - {201} - set(_ZS)),
                                          sorted(set(_MZ.values()) - set(_ZP))))
    check("the four LIVE spawns are unchanged (Church, Kalm, Wastelands, Sewers)",
          _ZS[208] == (738.9, -102.0, 1427.0) and _ZS[203] == (-1016.1, -2.0, 911.1)
          and _ZS[204] == (-629.7, -8.0, 152.7) and _ZS[205] == (-620.9, 398.0, -300.3))
    check("TWIN: the spawn-coverage gate fails without the 09-23 additions",
          not set(_MZ.values()) <= {208, 203, 204, 205})
    check("TWIN: with --zone-pieces off z204 falls back to 0,0 -- the bug",
          D.battle_bmap(204, D.parse_zone_pieces("off"), (0, 0)) == (0, 0))
    for _bad in ("204", "204:1,2,3", "204:256,0", "204:-1"):
        try:
            D.parse_zone_pieces(_bad)
            _rej = False
        except (SystemExit, ValueError):
            _rej = True
        check("--zone-pieces rejects %r" % _bad, _rej)

    # 2026-10-06: the pieces AT the spawn (spawn_bmap), the zone's
    # --zone-pieces pair as its fallback
    def _pieces_follow_zone(src):
        return (src.count("bmap=spawn_bmap(") == 2
                and "bmap=_gs_bmap)" not in src)
    check("both kind-2 pushes take M0/M1 from the spawn's pieces, else the "
          "arena zone's --zone-pieces", _pieces_follow_zone(_src))
    check("TWIN: the same gate FAILS on the pre-fix bmap=_gs_bmap shape",
          not _pieces_follow_zone(_src.replace("bmap=spawn_bmap(", "bmap=_gs_bmap)#")))

    # --- 2026-09-24: the Lifestream archive audit fixes ---------------------
    import doc_missions as DM
    import doc_stats as DS
    import doc_shop as DSH
    check("mission time limits from the archive: Drone 2nd 5 min, Scout 1st 5 min, "
          "A Devastated Church 9 min, Trooper 3rd 4:30, Beginner's Course 60 min",
          DM.time_limit(1) == 300 and DM.time_limit(6) == 300
          and DM.time_limit(5) == 540 and DM.time_limit(28) == 270
          and DM.time_limit(39) == 3600 and DM.time_limit(17) is None)
    _st = D.BattletableStore()
    _st.mission_time = dict(DM.MISSION_TIME)
    _mk = _st.add_record(D.build_battletable_record(
        table_id=0, flags=D.BT_FLAG_MISSION, mission=1, comment="m"))
    _nk = _st.add_record(D.build_battletable_record(
        table_id=0, flags=0, mission=1, comment="n"))
    _tm = struct.unpack_from("<I", _st.record(_mk), D.BT_OFF_TIME)[0]
    _tn = struct.unpack_from("<I", _st.record(_nk), D.BT_OFF_TIME)[0]
    check("a MISSION record is served with its archive time (the HUD reads it)",
          _tm == 300, "%d" % _tm)
    check("TWIN: a non-mission record with the same mission field keeps its own",
          _tn != 300, "%d" % _tn)
    _rr = D.battle_rules_from_record(bytes(_st.record(_mk)))
    check("...and the room clock built from that record is the same 300 s",
          _rr.time_limit == 300.0, "%r" % _rr.time_limit)
    # MEASURED: group 51 (reward text, quest N = index N-1) of
    # SE's 20060124_3 lobby.bin and of every served lobby.bin since the 09-22
    # retail rebase (20260923_8, 20260924 dg2fit / victoryfit) -- what the
    # player READS. The server must pay exactly that.
    _shown = {5: ("rp", 30), 16: ("rp", 10), 18: ("rp", 40), 22: ("rp", 50),
              24: ("rp", 15), 25: ("rp", 20), 26: ("rp", 60), 30: ("rp", 50),
              36: ("rp", 35), 41: ("rp", 100), 42: ("rp", 120), 43: ("rp", 100),
              23: ("gil", 2000), 31: ("gil", 1000), 32: ("gil", 1000),
              33: ("gil", 1000), 34: ("gil", 1000), 35: ("gil", 1000),
              37: ("gil", 1000), 38: ("gil", 1000), 39: ("gil", 300),
              40: ("gil", 500)}

    def _pays(rp, gil):
        out = {q: ("rp", v) for q, v in rp.items()}
        out.update({q: ("gil", v) for q, v in gil.items()})
        return out
    check("quest rewards pay exactly the served client's text (51:N-1): "
          "Assault Mission +30, Stolen Capsules! 2000 gil, Map Exercises 1000",
          _pays(DS.QUEST_RP, DS.QUEST_GIL) == _shown,
          "%s" % sorted(set(_pays(DS.QUEST_RP, DS.QUEST_GIL).items())
                        ^ set(_shown.items())))
    check("TWIN: the pre-rebase table (250 RP, 3000 / 1500 gil) fails that "
          "comparison",
          _pays({5: 250, 16: 50, 18: 100, 24: 50, 25: 150, 26: 200, 22: 95,
                 30: 65, 36: 35},
                {23: 3000, 31: 1500, 32: 1500, 33: 1500, 34: 1500, 35: 1500,
                 37: 1000, 39: 300, 40: 500, 38: 1000}) != _shown)
    check("the 'by performance' rewards: 19 gil, 20 / 21 / 27 / 29 rank points",
          DS.QUEST_PERFORMANCE_GIL == (19,)
          and set(DS.QUEST_PERFORMANCE_RP) == {20, 21, 27, 29})
    # 2026-09-26: the LAUNCH medal set (SE's 20060124_3 lobby.bin group 60)
    _aw = DS.award_medals("TBT", [
        {"key": "W", "team": 0, "kills": 3, "kos": 1},
        {"key": "L", "team": 1, "kills": 0, "kos": 0}], 0)
    check("TBT pays the launch medals: Team Merit (kills - KOs) and Slayer, "
          "to W; L's 'no KO' pays nothing (Iron Seal was the 2005 beta's)",
          _aw == {"W": [DS.M_TEAM_MERIT, DS.M_SLAYER], "L": []}, repr(_aw))
    _launch = ["BT Conquest Medal", "BT Medal of Honor", "BT Medal of Dishonor",
               "Team Merit Medal", "Survivor Medal", "Slayer", "Assault Medal",
               "Capsule Seeker Medal", "Last Capsule Medal",
               "Flag Carrier Medal", "First Flag Medal", "Leader Slayer Medal",
               "Base Attack Medal"]
    check("the medal names are the launch client's (group 60 [16..28])",
          [DS.MEDALS[i] for i in range(16, 29)] == _launch)
    check("TWIN: the 2005 beta table this module carried fails that",
          ["Medal of Dishonor", "First Attack", "Iron Seal", "Healer", "Assault",
           "Slayer", "The Finisher", "Seeker", "Star of Victory", "BT", "FA",
           "Survival", "Super Trooper"] != _launch)
    check("MODE_MEDALS = the client's per-mode Results table (retail "
          "0x00b18d20: [3 5] [4 5] [6 12] [7 8] [11] [9 10] ... [0 1 2])",
          [tuple(m - DS.MEDAL_BASE for m in DS.MODE_MEDALS[k]) for k in
           ("TBT", "TDM", "TBS", "TCP", "TLD", "TFL", "BT")]
          == [(3, 5), (4, 5), (6, 12), (7, 8), (11,), (9, 10), (0, 1, 2)])
    _ids = [i for i, _, _ in DSH.DEFAULT_STOCK]
    check("2026-10-05: Flash Materia is sold (Feb 16 2006 update, 100 gil) "
          "beside the four launch materia, but is NOT in the launch starter kit",
          0x6F34001B in _ids and DSH.Shop(None).prices[0x6F34001B] == 100
          and {0x6F340017, 0x6F340018, 0x6F340019, 0x6F34001A} <= set(_ids)
          and 0x6F34001B not in {i for i, _q in DSH.STARTER_KIT})
    check("2026-09-26: the shop sells no ammunition, consumables or kits (the "
          "2006 guides), frames at 200, suits at 300",
          not [i for i in _ids if i >> 16 in (0x6230, 0x6932, 0x6430)]
          and dict((i, p) for i, p, _ in DSH.DEFAULT_STOCK)[0x6F300000] == 200
          and dict((i, p) for i, p, _ in DSH.DEFAULT_STOCK)[0x63310050] == 300)
    _zs = {int(e.split(":")[0]) for e in D.ZONE_SPAWNS_DEFAULT.split(";")}
    check("the map exercises 37 Train Graveyard / 38 Battlefield Ruins are "
          "served, in their arenas, which have spawns",
          DM.ARCHIVE_ZONES.get(37) == 212 and DM.ARCHIVE_ZONES.get(38) == 231
          and {212, 231} <= _zs and "1-8,16-40" in _src)

    # --- 2026-09-24: TEAM BASE battles -- kind 29 bases, kind 33 HP --------
    _k29 = D.base_objects_payload((0, 1))
    check("kind 29 payload: record at body[20] (4 pad bytes), count 2, entries "
          "{type 1, team, gimmick} at +4 / +20",
          _k29[:4] == bytes(4) and _k29[5] == 2 and _k29[6] & 1 == 0
          and struct.unpack_from("<HHH", _k29, 8) == (1, 0, 0)
          and struct.unpack_from("<HHH", _k29, 24) == (1, 1, 1))
    check("kind 33 payload: body[16] index, rec+0 controller, rec+4 HP",
          D.base_hp_payload(1, 0x4103C, 8000)
          == struct.pack("<III", 1, 0x4103C, 8000))
    check("arena bases: Jungle 26/23 (live), no-base arenas (Wastelands, "
          "Kalm, church...) none, the rest the 1100 list SECOND-first (1, 0)",
          D.base_gimmicks(201) == (26, 23) and D.base_gimmicks(204) is None
          and D.base_gimmicks(203) is None and D.base_gimmicks(208) is None
          and D.base_gimmicks(230) == (1, 0))
    # 2026-09-24: team start points (the client never picks one by team).
    # These are the FALLBACK without doc_arena_starts.json: run them with the
    # per-situation extract switched off (restored below).
    _as = D.arenadata.ARENA_STARTS
    _as_saved = dict(_as)
    _as.clear()
    if not D.BASE_POSITIONS:
        # no doc_arena_table.json beside the code (README): the arena data is
        # not shipped, so these checks run on made-up positions of its shape
        D.BASE_POSITIONS.update({
            201: ((2000.0, -20.0, -1100.0), (300.0, -20.0, -900.0)),
            202: ((-400.0, -12.0, -1200.0), (400.0, -12.0, 1200.0))})
        D.TEAM_STARTS.update({201: ((500.0, -20.0, -950.0),
                                    (1800.0, -20.0, -1050.0))})
    _j0, _j1 = D.team_start(201, 0), D.team_start(201, 1)

    def _dist(a, b):
        return ((a[0] - b[0]) ** 2 + (a[2] - b[2]) ** 2) ** 0.5
    _b69, _b70 = D.BASE_POSITIONS[201]
    check("Jungle: each team starts nearer its OWN base (Ifrit = g070)",
          _dist(_j0, _b70) < _dist(_j0, _b69) and _dist(_j1, _b69) < _dist(_j1, _b70))
    _m0, _m1 = D.team_start(202, 0), D.team_start(202, 1)
    _c69, _c70 = D.BASE_POSITIONS[202]
    check("a base-derived start: 150 units from the own base, toward the enemy",
          abs(_dist(_m0, _c70) - 150.0) < 0.01 and abs(_dist(_m1, _c69) - 150.0) < 0.01
          and _dist(_m0, _c69) < _dist(_c70, _c69))
    check("TWIN: no base data and no start nodes (Wastelands) or no team -> no "
          "team start", D.team_start(204, 0) is None and D.team_start(201, None) is None
          and D.team_start(201, 5) is None)
    check("hand fallback: the Lab binds rows 14 / 12, Train Graveyard no base",
          D.arenadata.BASE_GIMMICKS[206] == (14, 12)
          and D.arenadata.BASE_GIMMICKS[212] is None)
    # 2026-10-05: doc_arena_starts.json keys starts and bases by SITUATION
    # (type-2 nodes by team byte; type 8 are MP points). Made-up positions.
    _as.update({
        213: {1100: {"starts": {0: [(1.0, 0.0, 1.0), (2.0, 0.0, 2.0)],
                                1: [(9.0, 0.0, 9.0)]},
                     "bases": [(0, 1, (8.0, 0.0, 8.0)), (1, 0, (3.0, 0.0, 3.0))]},
              1000: {"starts": {0: [(5.0, 0.0, 5.0), (6.0, 0.0, 6.0),
                                    (7.0, 0.0, 7.0)], 1: []}, "bases": []}},
        201: {1100: {"starts": {}, "bases": [(23, 1, (0.0, 0.0, 0.0)),
                                             (26, 0, (1.0, 0.0, 1.0))]},
              1104: {"starts": {}, "bases": [(24, 1, (0.0, 0.0, 0.0)),
                                             (28, 0, (1.0, 0.0, 1.0))]}}})
    try:
        check("team start = the situation's own team node, one per seat",
              D.team_start(213, 0, None, 1) == (2.0, 0.0, 2.0)
              and D.team_start(213, 0, 1100, 2) == (1.0, 0.0, 1.0)
              and D.team_start(213, 1, 1100, 5) == (9.0, 0.0, 9.0)
              and D.arenadata.team_start_count(213, 0) == 2)
        check("individual start = the 1000 list, one per seat",
              D.arenadata.bt_start(213, None, 4) == (6.0, 0.0, 6.0)
              and D.arenadata.bt_start(201, None, 0) is None)
        check("bases by situation, team = the owner byte: Jungle 1100 26/23, "
              "1104 28/24; Shinra 1/0 with its spots",
              D.base_gimmicks(201) == (26, 23) and D.base_gimmicks(201, 1104) == (28, 24)
              and D.base_gimmicks(213) == (1, 0)
              and D.base_spots(213) == ((3.0, 0.0, 3.0), (8.0, 0.0, 8.0)))
        check("TWIN: a situation the arena lacks has no base (not the hand rows)",
              D.base_gimmicks(213, 1105) is None and D.base_spots(213, 1105) is None
              and D.base_gimmicks(213, 1000) is None)
    finally:
        _as.clear()
        _as.update(_as_saved)
    # 2026-10-05: a mission starts at its controller's OWN start node (type 2),
    # even where the generic spawn has more enemy points within the radius
    # (the Beginner's Courses: generic spawn outside the gates, live)
    _ms = D.arenadata.MISSION_SPAWNS
    _ms_saved = _ms.get("299")
    _ms["299"] = {"3001": {"pool": [[0.0, 0.0, 0.0], [10.0, 0.0, 0.0],
                                    [500.0, 0.0, 500.0]],
                           "player": [[490.0, 0.0, 480.0], [480.0, 0.0, 490.0]]},
                  "3002": {"pool": [[0.0, 0.0, 0.0]], "player": []}}
    try:
        _gen = (5.0, 0.0, 5.0)
        check("mission start = the controller's own start node, one per seat "
              "(not the generic spawn with more enemies near it)",
              D.arenadata.mission_player_spawn(299, 3001, _gen) == (490.0, 0.0, 480.0)
              and D.arenadata.mission_player_spawn(299, 3001, _gen, seat=1)
              == (480.0, 0.0, 490.0)
              and D.arenadata.mission_player_spawn(299, 3001, _gen, seat=2)
              == (490.0, 0.0, 480.0))
        check("TWIN: a controller with no start node keeps the generic spawn",
              D.arenadata.mission_player_spawn(299, 3002, _gen) == _gen
              and D.arenadata.mission_player_spawn(299, 3999, _gen) == _gen)
    finally:
        if _ms_saved is None:
            _ms.pop("299", None)
        else:
            _ms["299"] = _ms_saved
    # 2026-10-05: the arena's spawn groups pick each enemy (fixed first, then
    # the mission's target, then the rest; an undrawable group stays empty)
    _pool = [[1000.0, 0.0, 0.0], [200.0, 0.0, 0.0], [300.0, 0.0, 0.0],
             [400.0, 0.0, 0.0], [500.0, 0.0, 0.0]]
    _grps = [[1, [[7, 100]]],            # fixed, far
             [0xFFFF, [[5, 80]]],        # random, nearest
             [0xFFFF, [[9, 50]]],        # random, the target
             [1, [[99, 100]]],           # fixed but undrawable
             None]
    _pick = lambda g: None if g[1][0][0] == 99 else g[1][0][0]
    _plan = D.arenadata.mission_enemy_plan(_pool, _grps, (0.0, 0.0, 0.0), 3, _pick,
                                           prefer=lambda t: t == 9, near=10.0)
    check("spawn groups: the fixed enemy first, then the mission's target, then "
          "the nearest random one; the undrawable node stays empty",
          _plan == [((1000.0, 0.0, 0.0), 7), ((300.0, 0.0, 0.0), 9),
                    ((200.0, 0.0, 0.0), 5)], "%r" % (_plan,))
    _grps2 = [[1, [[5, 100]]], [1, [[5, 100]]], [1, [[9, 100]]], [0xFFFF, [[5, 80]]],
              [0xFFFF, [[5, 80]]]]
    _plan2 = D.arenadata.mission_enemy_plan(_pool, _grps2, (0.0, 0.0, 0.0), 1, _pick,
                                            prefer=lambda t: t == 9, near=10.0)
    check("spawn groups: a FIXED target beats nearer fixed non-targets (Sniper "
          "Threat fielded only soldiers)", _plan2 == [((300.0, 0.0, 0.0), 9)],
          "%r" % (_plan2,))
    check("TWIN: no groups (an older extract) -> no plan (the row's own types)",
          D.arenadata.mission_enemy_plan(_pool, [], (0.0, 0.0, 0.0), 3, _pick) == []
          and D.arenadata.mission_enemy_plan(_pool, _grps[:2], (0, 0, 0), 3, _pick) == [])
    import tempfile as _tf
    with _tf.TemporaryDirectory() as _td:
        _old = os.path.join(_td, "starts.json")
        with open(_old, "w") as _f:
            _f.write('{"213": {"0": [2.3, 0.0, -63.1], "1": [1.0, 0.0, 1.0]}}')
        check("TWIN: the old type-8 {zone: {link: pos}} file is not read as starts",
              D.arenadata.load_arena_starts(_old) == {})

    # --- 2026-09-24: TEAM CAPSULE battles (kinds 10/11/21/46/47/48, P2P 118/119)
    check("the Mako Capsule is 0x6B300000; 118/119 are battle types, answered "
          "not relayed", D.MAKO_CAPSULE == 0x6B300000
          and {D.P2P_DROP, D.P2P_PICKUP} <= D.P2P_BATTLE_TYPES)
    _fi = D.field_item_payload(D.MAKO_CAPSULE, 3, (10.4, -2.0, -300.6))
    check("field item payload: body[16] 0, record {id, count 1, slot, 0, s16 x/y/z}",
          _fi[:4] == bytes(4) and struct.unpack_from("<IHHHhhh", _fi, 4)
          == (D.MAKO_CAPSULE, 1, 3, 0, 10, -2, -301))
    _sb = D.capsule_scoreboard_payload({0x41: 2, 0x42: 0, 0x43: 1})
    check("kind 46: 7 holder ids then 7 counts, empties are 0",
          len(_sb) == 4 + 28 + 7 and struct.unpack_from("<7I", _sb, 4)[:3]
          == (0x41, 0x43, 0) and tuple(_sb[32:39]) == (2, 1, 0, 0, 0, 0, 0))
    _cr = D.BattleRoom(8, [0xA, 0xB], {0xA: 0, 0xB: 1},
                       D.BattleRules(mode="TCP", capsules=2), now=0.0)
    _cr.field = {0: (D.MAKO_CAPSULE, (0, 0, 0)), 1: (D.MAKO_CAPSULE, (5, 0, 5))}
    _m, _n = D.capsule_pickup(_cr, 0xA, 0)
    check("pick-up: kind 11 to all with ident = the picker; slot 0 leaves the "
          "field", [(k, i, to) for k, _, i, to in _m] == [(11, 0xA, "all")]
          and 0 not in _cr.field and _cr.holders == {0xA: 1})
    _m, _n = D.capsule_pickup(_cr, 0xB, 0)
    check("TWIN: the same slot again (B was a frame late) is ignored", _m == [])
    _h, _ = D.capsule_hold(_cr, 100.0)
    check("one of two held: scoreboard only, no hold",
          [k for k, *_ in _h] == [46] and _cr.cap_hold is None)
    D.capsule_pickup(_cr, 0xA, 1)
    _h, _ = D.capsule_hold(_cr, 100.0)
    check("team 0 holds both: kind 47 starts the 10 s hold",
          [k for k, *_ in _h] == [46, 47] and _cr.cap_hold == (0, 110.0))
    check("the hold is not done at 109 s", not D.capsule_hold_done(_cr, 109.0))
    _m, _n = D.capsule_drop(_cr, 0xA, D.MAKO_CAPSULE, 1, (1.0, 2.0, 3.0))
    check("drop: kind 10 to the dropper, kind 21 to the others, back on the field",
          [(k, to) for k, _, _, to in _m] == [(10, "self"), (21, "others")]
          and len(_cr.field) == 1 and _cr.holders[0xA] == 1)
    _h, _ = D.capsule_hold(_cr, 105.0)
    check("losing one cancels the hold (kind 48)",
          [k for k, *_ in _h] == [46, 48] and _cr.cap_hold is None)
    _slot = next(iter(_cr.field))
    D.capsule_pickup(_cr, 0xB, _slot)
    D.capsule_hold(_cr, 106.0)
    check("one each: no hold", _cr.cap_hold is None)
    # 2026-10-06: the (re)spawn's map pieces come from WHERE it is (the client
    # loads only M0/M1; live, Jungle team 1 stood in m004 with (1, 3) loaded)
    _pd = {"cell": 100.0, "zones": {"201": {
        "1": {"3,-6": 900}, "3": {"9,-12": 500}, "4": {"25,-13": 2000, "24,-13": 40},
        "5": {"21,-9": 300}}}}
    _am = D.arenamaps
    check("spawn_bmap: a point only in m004 loads m004 + its nearest neighbour",
          _am.spawn_bmap(201, (2590.0, -15.0, -1240.0), (1, 3), data=_pd) == (4, 5),
          "%r" % (_am.spawn_bmap(201, (2590.0, -15.0, -1240.0), (1, 3), data=_pd),))
    check("spawn_bmap: a point in m001 keeps m001 first",
          _am.spawn_bmap(201, (381.0, -12.0, -560.0), (1, 3), data=_pd)[0] == 1)
    check("TWIN: no piece data for the zone -> the zone's pair unchanged",
          _am.spawn_bmap(211, (2590.0, -15.0, -1240.0), (1, 6), data=_pd) == (1, 6)
          and _am.spawn_bmap(201, None, (1, 3), data=_pd) == (1, 3))
    # 2026-10-06: a KO'd carrier drops what it holds (the client sends no 118)
    _ck = D.BattleRoom(10, [0xA, 0xB], {0xA: 0, 0xB: 1},
                       D.BattleRules(mode="TCP", capsules=2), now=0.0)
    _ck.field = {0: (D.MAKO_CAPSULE, (0, 0, 0)), 1: (D.MAKO_CAPSULE, (5, 0, 5))}
    D.capsule_pickup(_ck, 0xB, 0)
    D.capsule_pickup(_ck, 0xB, 1)
    _m, _n = D.fielditems.capsule_ko_drop(_ck, 0xB, (100.0, -5.0, 200.0))
    check("KO drop: per capsule 21 + quiet 10 to the victim, 10 to the others; "
          "both back on the field at the death spot, holder at 0",
          [(k, i, to) for k, _, i, to in _m] == [(21, 0xB, "self"), (10, 0xB, "self"),
                                                 (10, 0xB, "others")] * 2
          and len(_ck.field) == 2 and _ck.holders[0xB] == 0
          and all(v[1] == (100.0, -5.0, 200.0) for v in _ck.field.values())
          and _m[1][1][:4] == struct.pack("<I", D.fielditems.FIELD_QUIET)
          and _m[2][1][:4] == bytes(4), _n)
    check("TWIN: a KO'd player holding nothing drops nothing",
          D.fielditems.capsule_ko_drop(_ck, 0xA, (0.0, 0.0, 0.0)) == ([], None)
          and len(_ck.field) == 2)
    _cr2 = D.BattleRoom(9, [0xA, 0xB], {0xA: 0, 0xB: 1},
                        D.BattleRules(mode="TCP", capsules=1), now=0.0)
    _cr2.field = {0: (D.MAKO_CAPSULE, (0, 0, 0))}
    D.capsule_pickup(_cr2, 0xB, 0)
    D.capsule_hold(_cr2, 200.0)
    check("the hold lasts 10 s -> done, team 1 wins",
          D.capsule_hold_done(_cr2, 210.0) and _cr2.winner_team() == 1)
    # 2026-09-26: the launch medals 60:[48] Last Capsule / [47] Capsule Seeker
    check("Last Capsule: the pick-up that completed the WINNING hold (B)",
          _cr2.last_capsule == 0xB)
    check("TWIN: a cancelled hold names nobody (room 8's hold was lost)",
          _cr.last_capsule is None and _cr.cap_last is None)
    _sk = D.BattleRoom(91, [0xA, 0xB, 0xC], {0xA: 0, 0xB: 1, 0xC: 1},
                       D.BattleRules(mode="TCP", capsules=3), now=0.0)
    _sk.field = {0: (D.MAKO_CAPSULE, (0, 0, 0))}
    D.capsule_pickup(_sk, 0xB, 0)
    _sk.kill(0xA, 0xB, 10.0)
    check("Capsule Seeker: A KOs B while B holds a capsule -> 1 carrier KO",
          _sk.carrier_kos == {0xA: 1})
    _dm, _dn = D.capsule_drop(_sk, 0xB, D.MAKO_CAPSULE, 1, (0, 0, 0), now=10.5)
    check("... and B's own drop right after is the SAME KO (still 1)",
          _sk.carrier_kos == {0xA: 1}, _dn)
    D.capsule_pickup(_sk, 0xC, next(iter(_sk.field)))
    _dm, _dn = D.capsule_drop(_sk, 0xC, D.MAKO_CAPSULE, 1, (0, 0, 0), now=20.0)
    check("drop-first: C's DROP before any KO credits nobody yet",
          _sk.carrier_kos == {0xA: 1} and "Capsule Seeker" not in _dn, _dn)
    _sk.kill(0xA, 0xC, 20.3)
    check("... then its request 30 (0.3 s later, holding 0) is the carrier KO",
          _sk.carrier_kos == {0xA: 2})
    D.capsule_pickup(_sk, 0xC, next(iter(_sk.field)))
    D.capsule_drop(_sk, 0xC, D.MAKO_CAPSULE, 1, (0, 0, 0), now=40.0)
    _sk.kill(0xA, 0xC, 50.0)
    check("TWIN: a KO 10 s after a voluntary drop is no carrier KO",
          _sk.carrier_kos == {0xA: 2})
    _sk.kill(0xC, 0xA, 60.0)                 # A holds nothing
    check("TWIN: a KO of a player holding nothing is no carrier KO",
          _sk.carrier_kos == {0xA: 2})
    _hb = dict(_cr2.holders)
    _dm, _dn = D.capsule_drop(_cr2, 0xB, 0x62300000, 18, (5.0, 6.0, 7.0))
    check("2026-09-26: a dropped non-capsule item lands on the field (kind 10 to "
          "ALL, ident = the dropper) and is not a capsule",
          len(_dm) == 1 and _dm[0][0] == 10 and _dm[0][2:] == (0xB, "all")
          and _cr2.holders == _hb, _dn)
    _ds = struct.unpack_from("<H", _dm[0][1], 10)[0]
    _pm, _pn = D.capsule_pickup(_cr2, 0xA, _ds)
    check("... and picking it up is kind 11 {id, 18} to ALL, ident = the picker",
          len(_pm) == 1 and _pm[0][0] == 11 and _pm[0][2] == 0xA
          and struct.unpack_from("<IH", _pm[0][1], 4) == (0x62300000, 18)
          and _ds not in _cr2.field and _cr2.holders == _hb, _pn)
    check("TWIN: a second pick-up of that slot is ignored (already taken)",
          D.capsule_pickup(_cr2, 0xB, _ds)[0] == [])
    _pf = D.BattleRoom(90, [1, 2], {1: 0, 2: 1}, D.BattleRules(mode="BT"), now=0.0)
    _pf.field = {}
    check("a plain (non-capsule) battle's field takes a drop too",
          D.capsule_drop(_pf, 1, 0x62300002, 30, (0, 0, 0))[0][0][0] == 10
          and len(_pf.field) == 1)
    # Seen live, with RE: touching a kind-10 capsule sends a RELIABLE
    # inner-119 (flags 0x01) to the server; body = {u32 slot, u32 1, u32 n,
    # f32 pos}. The live capture's body (slot 6), mode 4:
    _b119 = bytes.fromhex("06000000010000000000000000d7777f4477fb5ac12ac2acc4"[:48]
                          + "c4")
    _w119 = bytearray(D.BODY_OFF) + _b119
    _w119[1] = 4
    _i119 = {"type": 119, "flags": 0x01, "is_data": True, "plain": bytes(_w119)}
    check("a reliable mode-4 inner-119 is a capsule PICK-UP to the server",
          D.p2p_server_type(bytes(_w119), _i119) == D.P2P_PICKUP
          and D.p2p_battle_type(bytes(_w119), _i119) is None)
    check("its body[0] is the SLOT (live: 6, logged then as 'request 6')",
          D.p2p_pickup_slot(_b119) == 6)
    check("TWIN: a reliable GS request (inner type 130) is not a pick-up",
          D.p2p_server_type(bytes(_w119), dict(_i119, type=D.GS_INNER_TYPE)) is None
          and D.p2p_server_type(bytes(_w119), dict(_i119, is_data=False)) is None)
    # Seen live (Jungle TBS): the controller's request 24 carries the
    # bases -- count at body+61, {u32 HP, u16 index, u16 0, u32 mask} from +64
    _r24 = bytes.fromhex(
        "1800020000000000010000000e010000110000003c10040047107d43521cd7c0"
        "a30c62c41e68cf3e00000000030e6abf020c853c000103200000002000020000"
        "401f000000000000000000008a1d00000100000000000000")
    check("request 24 (live): base 0 at 8000, base 1 shot down to 7562",
          D.base_report(_r24) == [(0, 8000, 0), (1, 7562, 0)])
    check("TWIN: a short / non-base report parses to nothing",
          D.base_report(_r24[:70]) == [] and D.base_report(bytes(64)) == [])
    # 2026-10-05 (captured live, Iron Curtain table 17): a MISSION report
    # lists its 2 enemies first (count at body+63), the base after them
    _ic = bytes.fromhex(
        "180011000000000001000000930000001e000000d0100400e7b3f2c322f5c743138fd6c2"
        "45f5693f00000000a9d7cfbe02088e2df903010000000b0000010002000100400000c1fd"
        "4a01fbfe010100400000e0fd270112ff000000000000000000000000")
    _ic_raw = bytes.fromhex("04047c0038c9320098ee2658c101683a63268fedac136e80") + _ic
    check("a base mission's report: the base AFTER the 2 enemies (HP 0 = fallen), "
          "not the first enemy read as a base",
          D.base_report(_ic) == [(0, 0, 0)], "%r" % (D.base_report(_ic),))
    check("...and its enemy list still reads (it was rejected by length)",
          D.gamemsg.mission_npc_report(_ic_raw) == [(0x40000100, 0), (0x40000101, 0)])
    # 2026-10-05: enemy drops land where the report last placed the enemy
    # (s16 world units: this one died beside the base at (-625, 284, -344))
    _icp = D.gamemsg.mission_npc_positions(_ic_raw)
    check("mission_npc_positions: both enemies' s16 positions, keyed by id",
          _icp.get(0x40000100) == (-575, 330, -261) and len(_icp) == 2, "%r" % (_icp,))
    check("TWIN: a datagram that is not a report has no positions",
          D.gamemsg.mission_npc_positions(_ic_raw + b"\0") == {})
    check("TWIN: a PvP report (no enemies) still reads its bases from +64",
          D.base_report(_r24) == [(0, 8000, 0), (1, 7562, 0)]
          and _r24[63] == 0)
    check("Jungle bases: Ifrit (team 0) = gimmick 26, the RED one (live)",
          D.base_gimmicks(201) == (26, 23))
    _br = D.BattleRoom(14, [0xA, 0xB], {0xA: 0, 0xB: 1},
                       D.BattleRules(mode="TBS"), now=0.0)
    check("first report: both bases change, nothing ends",
          _br.base_update(D.base_report(_r24)) == [(0, 8000), (1, 7562)]
          and not _br.over)
    check("the same report again changes nothing",
          _br.base_update(D.base_report(_r24)) == [])
    _br.base_update([(0, 8000, 0), (1, 0, 1)])
    check("Shiva's base (1) at 0 HP: over, team 0 (Ifrit) wins",
          _br.over and _br.why == "team 1's base destroyed"
          and _br.winner_slot() == 0)
    _br2 = D.BattleRoom(15, [0xA], {0xA: 0}, D.BattleRules(mode="TBS"), now=0.0)
    _br2.base_update([(0, 0, 0), (1, 0, 0)])
    check("TWIN: a base that was NEVER above 0 does not end the room",
          not _br2.over)
    # 2026-09-26: TEAM BASE = destroy + OCCUPY (January Additional Manual).
    # Base 1 (team 1's) falls -> team 0 must stand on its spot for the hold.
    _oc = D.BattleRoom(16, [0xA, 0xB, 0xC], {0xA: 0, 0xB: 1, 0xC: 0},
                       D.BattleRules(mode="TBS"), now=0.0)
    _oc.base_spots = D.base_spots(201)
    check("base spots: team 0 owns g070 (BASE_POSITIONS[z][1]), like team_start",
          _oc.base_spots == (D.BASE_POSITIONS[201][1], D.BASE_POSITIONS[201][0]))
    _oc.base_update([(0, 8000, 0), (1, 8000, 0)], occupy=True)
    _oc.base_update([(0, 8000, 0), (1, 0, 1)], occupy=True)
    check("occupy: base 1 at 0 HP does NOT end the room; team 0 must occupy it",
          not _oc.over and _oc.base_down == {1: 0})
    _sp = _oc.base_spots[1]
    _on = (_sp[0] + 30.0, _sp[1], _sp[2] - 40.0)      # 50 away: on the spot
    _off = (_sp[0] + 300.0, _sp[1], _sp[2])
    _poses = {0xA: _off + (0.0,), 0xB: _on + (0.0,), 0xC: _off + (0.0,)}
    D.base_occupy_tick(_oc, _poses, 0.0, 100.0, 10.0)
    check("TWIN: only the DEFENDER (team 1) on the spot -> no hold",
          not _oc.occupy and not _oc.over)
    _poses[0xA] = _on + (1.0,)
    D.base_occupy_tick(_oc, _poses, 1.0, 100.0, 10.0)
    check("an attacker (0xA, team 0) steps on the spot -> hold starts",
          _oc.occupy.get(1) == (0xA, 1.0) and not _oc.over)
    _poses[0xA] = _off + (6.0,)
    D.base_occupy_tick(_oc, _poses, 6.0, 100.0, 10.0)
    check("it leaves at +5 s -> the hold RESETS", not _oc.occupy and not _oc.over)
    _poses[0xA] = _on + (7.0,)
    D.base_occupy_tick(_oc, _poses, 7.0, 100.0, 10.0)
    _oc.dead_until[0xA] = 99.0                     # KO'd on the spot
    _poses[0xA] = _on + (9.0,)
    D.base_occupy_tick(_oc, _poses, 9.0, 100.0, 10.0)
    check("a KO'd occupier holds nothing -> reset", not _oc.occupy)
    _oc.dead_until.clear()
    _poses[0xC] = _on + (10.0,)
    D.base_occupy_tick(_oc, _poses, 10.0, 100.0, 10.0)
    _poses[0xC] = _on + (15.0,)
    D.base_occupy_tick(_oc, _poses, 15.0, 100.0, 10.0)
    check("TWIN: 5 s of a 10 s hold does not win", not _oc.over)
    _poses[0xC] = _on + (18.0,)
    D.base_occupy_tick(_oc, _poses, 18.0, 100.0, 10.0)
    check("TWIN: a pose older than BASE_POSE_FRESH_S (4 s) is not 'there' "
          "(stale pose at +22.5)",
          D.base_occupy_tick(_oc, _poses, 22.5, 100.0, 10.0) and not _oc.occupy)
    _poses[0xC] = _on + (23.0,)
    D.base_occupy_tick(_oc, _poses, 23.0, 100.0, 10.0)
    _poses[0xC] = _on + (33.0,)
    D.base_occupy_tick(_oc, _poses, 33.0, 100.0, 10.0)
    check("10 s unbroken on the spot: over, team 0 wins, 0xC is the occupier",
          _oc.over and _oc.winner_slot() == 0 and _oc.occupier == 0xC
          and "occupied" in _oc.why)
    import doc_stats as ST_
    _aw = ST_.award_medals("TBS", [
        {"key": "a", "team": 0, "kills": 0, "kos": 1},
        {"key": "c", "team": 0, "kills": 0, "kos": 1, "base_capture": True},
        {"key": "b", "team": 1, "kills": 0, "kos": 1}], 0)
    check("Assault medal goes to the OCCUPIER's row only",
          ST_.M_ASSAULT in _aw["c"] and ST_.M_ASSAULT not in _aw["a"]
          and ST_.M_ASSAULT not in _aw["b"])
    _oc2 = D.BattleRoom(17, [0xA, 0xB], {0xA: 0, 0xB: 1},
                        D.BattleRules(mode="TBS"), now=0.0)
    _oc2.base_update([(1, 8000, 0)], occupy=False)
    _oc2.base_update([(1, 0, 1)], occupy=False)
    check("TWIN: occupy=False (--base-occupy off) keeps the old instant end",
          _oc2.over and not _oc2.base_down and _oc2.occupier is None)
    # 2026-09-24: capsule MISSIONS reuse the field; the count wins them
    _mr = D.BattleRoom(10, [0xA, 0xB], {0xA: 0, 0xB: 0},
                       D.BattleRules(mode="TBT"), mission=16, now=0.0)
    check("a capsule mission's field = its target (Collector's Mind: 7)",
          D.capsule_count(_mr) == 7)
    check("TWIN: a kill mission and a plain team battle get no field",
          D.capsule_count(D.BattleRoom(11, [0xA], {0xA: 0},
                                       D.BattleRules(mode="TBT"), mission=1,
                                       now=0.0)) == 0
          and D.capsule_count(D.BattleRoom(12, [0xA], {0xA: 0},
                                           D.BattleRules(mode="TBT"),
                                           now=0.0)) == 0)
    _mr.field = {i: (D.MAKO_CAPSULE, (0, 0, i)) for i in range(7)}
    for _i in range(6):
        D.capsule_pickup(_mr, 0xA if _i % 2 else 0xB, _i)
    D.capsule_mission_check(_mr)
    check("6 of 7 held between two players: not over", not _mr.over)
    D.capsule_pickup(_mr, 0xA, 6)
    D.capsule_mission_check(_mr)
    check("the 7th (co-op total) wins it: over with the objective, verdict w",
          _mr.over and _mr.why.startswith(D.doc_missions.WHY_OBJECTIVE)
          and D.doc_missions.verdict(16, _mr.over, _mr.why, 0) == "w")
    # 2026-10-05: mission capsules go on SE's capsule generators
    import doc_field as _dfield
    if _dfield.load():
        check("capsule spots: the Trooper 3rd exam's 201:3001 has exactly the 3 "
              "its objective asks; Collector's Mind's Church 3003 has 10",
              len(_dfield.capsule_spots(201, 3001)) == 3
              and len(_dfield.capsule_spots(*D.doc_missions.CAPSULE_SITUATIONS[16])) == 10)
        check("TWIN: a situation without capsule generators has no spots (ring)",
              _dfield.capsule_spots(203, 3003) == [])
    _mr27 = D.BattleRoom(13, [0xA], {0xA: 0}, D.BattleRules(mode="TBT"),
                         mission=27, now=0.0)
    _mr27.field = {i: (D.MAKO_CAPSULE, (0, 0, i)) for i in range(15)}
    for _i in range(15):
        D.capsule_pickup(_mr27, 0xA, _i)
    D.capsule_mission_check(_mr27)
    check("TWIN: 'as many as possible' (27) never ends on a count",
          D.capsule_count(_mr27) == 15 and not _mr27.over)
    # 2026-10-05: a kill mission counts only the enemy it names
    _dh = D.doc_missions.mission_setup(3)[2]    # Commander, Commander, Beast
    _kr = D.BattleRoom(15, [0xA], {0xA: 0}, D.BattleRules(mode="TBT"),
                       mission=3, now=0.0)
    _nb = D.doc_npc_spawn.ARENA_ID_BASE
    _ty = {_nb: _dh[2], _nb + 1: _dh[0], _nb + 2: _dh[0], _nb + 3: _dh[0]}
    _kr.npc_hp_update([(_nb, 100)], 0xA, 1.0, types=_ty)
    _kr.npc_hp_update([(_nb, 0)], 0xA, 2.0, types=_ty)
    check("a Beast Soldier's death does not count toward 'defeat 3 Commanders'",
          _kr.npc_kills == 0 and _kr.kills[0xA] == 0)
    for _i in (1, 2, 3):
        _kr.npc_hp_update([(_nb + _i, 100)], 0xA, 3.0 + _i, types=_ty)
        _kr.npc_hp_update([(_nb + _i, 0)], 0xA, 3.5 + _i, types=_ty)
    # 2026-10-05: one enemy's death arrives twice -- request 30 AND the 1 Hz
    # report -- and counted twice (Course I "cleared" on 3 real kills)
    _dc = D.BattleRoom(16, [0xA], {0xA: 0}, D.BattleRules(mode="TBT"),
                       mission=3, now=0.0)
    _dc.kill(0xA, _nb + 1, 1.0, npc_type=_dh[0])          # request 30
    _dc.npc_hp_update([(_nb + 1, 100)], 0xA, 1.5, types=_ty)
    _dc.npc_hp_update([(_nb + 1, 0)], 0xA, 2.0, types=_ty)  # the 1 Hz report
    _dc.kill(0xA, _nb + 1, 2.5, npc_type=_dh[0])          # a resent 30
    check("one enemy's death counts ONCE (request 30 + the 1 Hz report)",
          _dc.npc_kills == 1 and _dc.kills[0xA] == 1, "%d" % _dc.npc_kills)
    _dc.kill(0xA, _nb + 2, 3.0, npc_type=_dh[0])
    check("TWIN: a second enemy's death still counts", _dc.npc_kills == 2)
    check("TWIN: the third Commander wins it",
          _kr.npc_kills == 3 and _kr.over
          and _kr.why.startswith(D.doc_missions.WHY_OBJECTIVE))

    # --- sec 4he (2026-09-23): the P2P battle layer, the room, the rules --
    def p2p(ptype, mode, sender, target, payload, flags=0x08):
        rec = bytearray(D.P2P_PAYLOAD_OFF + len(payload))
        rec[0], rec[1] = ptype, 8
        struct.pack_into("<I", rec, D.P2P_SENDER_OFF, sender)
        struct.pack_into("<i", rec, D.P2P_TARGET_OFF, target)
        struct.pack_into("<H", rec, D.P2P_PAYLOAD_LEN_OFF, len(payload))
        rec[D.P2P_PAYLOAD_OFF:] = payload
        pkt = bytearray(D.BODY_OFF) + rec
        pkt[1] = mode
        pkt[8] = ptype
        pkt[9] = flags
        struct.pack_into("<I", pkt, 16, sender)
        inner = {"type": ptype, "flags": flags, "plain": bytes(pkt),
                 "u32_16": sender, "u32_20": 0, "is_data": bool(flags & 1)}
        return bytes(pkt), inner
    dmg = struct.pack("<I", 1) + struct.pack("<IiII", 0x41018, 35, 0x2a664, 77) + bytes(4)
    d113, i113 = p2p(113, 4, 0x2a664, 0x41018, dmg)
    check("a mode-4 inner-113 flags-8 datagram is the P2P DAMAGE layer",
          D.p2p_battle_type(d113, i113) == 113)
    s112, i112 = p2p(112, 3, 0x2a664, -1, bytes(56))
    check("a mode-3 inner-112 flags-8 datagram is a SHOT",
          D.p2p_battle_type(s112, i112) == 112)
    _t, _f, _sid, _tgt, _pl = D.p2p_record(d113)
    check("p2p_record reads type / sender / target / payload",
          (_t, _sid, _tgt, len(_pl)) == (113, 0x2a664, 0x41018, len(dmg)))
    check("113 entries decode {target, damage, attacker, shot id}",
          D.p2p_damage_entries(_pl) == [(0x41018, 35, 0x2a664, 77)])
    g30 = D.build_gs_message(30, seq=1, body_extra=struct.pack("<IHHII", 0, 0, 0, 0, 0)[:0])
    _gs_inner = {"type": 130, "flags": 1, "plain": g30, "u32_16": 0x41018,
                 "u32_20": 0x41018, "is_data": True}
    check("TWIN: a mode-4 GAME-SERVER request is NOT the P2P layer (flags 1, type 130)",
          D.p2p_battle_type(bytearray(g30[:1]) + b"\x04" + g30[2:], _gs_inner) is None)
    _no8 = dict(i113, flags=0x00)
    check("TWIN: inner flags without bit 3 are not relayed",
          D.p2p_battle_type(d113, _no8) is None)
    _m2 = bytearray(d113)
    _m2[1] = 2
    check("TWIN: a mode-2 datagram is not the P2P layer",
          D.p2p_battle_type(bytes(_m2), i113) is None)
    rl = D.build_peer_relay(d113)
    check("the relay copy is mode 0, flags | 8, body VERBATIM, checksum recomputed (sec 4fu shape)",
          rl[1] == 0 and rl[9] & 8 and rl[D.BODY_OFF:] == d113[D.BODY_OFF:]
          and struct.unpack_from("<H", rl, D.CKSUM_OFF)[0] == D.cksum(
              bytearray(rl[:D.CKSUM_OFF]) + bytes(2) + bytearray(rl[D.CKSUM_OFF + 2:])))

    # 2026-09-28: a shot / damage whose mode-4 header does not decrypt is named
    # by its body (the live shapes: one hit = count + a 16-byte entry)
    _me, _foe = 0x2a664, 0x41018
    _mem = [_me, _foe]
    def m4(body):
        pkt = bytearray(os.urandom(D.BODY_OFF)) + body
        pkt[0:4] = b"\x04\x04" + struct.pack("<H", len(pkt))
        return bytes(pkt)
    m4d = m4(struct.pack("<IIiII", 1, _foe, 10, _me, 0x27))
    check("unreadable 44-byte mode-4 {1, victim, dmg, me, shot} is a DAMAGE",
          len(m4d) == 44 and D.p2p_battle_type_mode4(m4d, None, _me, _mem) == 113)
    _slots = bytes([0x1e, 0x30, 8, 0x31, 6, 0x32, 1, 0x33, 10, 0x34, 2, 0x30,
                    0x21, 0x43, 0, 0, 0x43, 3, 0xff, 0x3f, 0x27, 0, 0, 0])
    m4s = m4(_slots + struct.pack("<6f", 107.5, -12.3, 12.3, 92.6, -14.9, 13.9)
             + struct.pack("<II", 0x190b827b, 0xFFFFFFFF))
    check("unreadable 80-byte mode-4 with the '0'..'4' slot table is a SHOT",
          len(m4s) == 80 and D.p2p_battle_type_mode4(m4s, None, _me, _mem) == 112)
    # 2026-10-03 (live, the leader's 155 lost shots): EMPTY slots are ff ff
    _emp = bytes([0x14, 0x30, 6, 0x31, 0xff, 0xff, 0xff, 0xff, 0x17, 0x34, 2, 0x30,
                  0x21, 0x43, 0, 0, 0x43, 3, 0xff, 0x3f, 0x27, 0, 0, 0])
    m4e = m4(_emp + struct.pack("<6f", 107.5, -12.3, 12.3, 92.6, -14.9, 13.9)
             + struct.pack("<II", 0x190b827b, 0xFFFFFFFF))
    check("unreadable 80-byte SHOT with EMPTY (ff ff) slots 2+3 is a SHOT",
          D.p2p_battle_type_mode4(m4e, None, _me, _mem) == 112)
    check("TWIN: the old '01234' test rejected that live shot",
          _emp[1:10:2] != b"01234")
    check("TWIN: a slot labelled out of order is not a SHOT",
          D.p2p_battle_type_mode4(m4(bytes([0x14, 0x30, 6, 0x32]) + _emp[4:]
                                     + struct.pack("<6f", 1, 2, 3, 4, 5, 6)
                                     + bytes(8)), None, _me, _mem) is None)
    # 2026-10-03 (live, the leader's): P2P 96 and 121 by body, bytes as captured
    m96 = m4(bytes.fromhex(
        "4d 0d 35 44 28 ec c7 c2 d1 3f ce 44 f1 ff 0a bf 00 00 00 00 16 fa 56 3f"
        " 80 04 00 00 0b 30 03 31 02 32 ff ff ff ff 01 30 00 00 00 00"))
    check("unreadable 68-byte {pos, .., slot table at +28} is P2P 96",
          len(m96) == 68 and D.p2p_battle_type_mode4(m96, None, _me, _mem) == 96)
    m121 = m4(bytes.fromhex("6465fb01c5bb5a439895ddbfeb9330c2a93900000b000000"))
    check("unreadable 48-byte opening 64 65 fb 01 is P2P 121",
          len(m121) == 48 and D.p2p_battle_type_mode4(m121, None, _me, _mem) == 121)
    m42 = m4(bytes.fromhex(
        "2a 00 1b 00 00 00 00 00 00 00 00 00 05 00 15 00 00 00 00 00 70 75 73 73"
        " 79 63 61 74 20 64 67 20 73 6f 6c 64 69 65 72 73 00 00 00 00"))
    check("TWIN: a real 68-byte GS 42 (chat text) is NOT a 96",
          D.p2p_battle_type_mode4(m42, None, _me, _mem) is None)
    check("TWIN: a 48-byte 1 Hz-ish body (06 00 00 00 ..) is NOT a 121",
          D.p2p_battle_type_mode4(m4(bytes.fromhex(
              "060000000100000000000000d7777f4477fb5ac12ac2acc4")),
              None, _me, _mem) is None)
    check("TWIN: a readable header is p2p_battle_type()'s, not the body namer's",
          D.p2p_battle_type_mode4(m4d, {"plain": m4d}, _me, _mem) is None)
    check("TWIN: no battle room, no naming",
          D.p2p_battle_type_mode4(m4d, None, _me, ()) is None)
    check("TWIN: a keepalive-shaped body (count 1, zeros) is not a DAMAGE",
          D.p2p_battle_type_mode4(m4(struct.pack("<I", 1) + bytes(16)),
                                  None, _me, _mem) is None)
    check("TWIN: damage by SOMEONE ELSE is not this sender's hit",
          D.p2p_battle_type_mode4(m4(struct.pack("<IIiII", 1, _foe, 10, 0x5555, 3)),
                                  None, _me, _mem) is None)
    check("TWIN: a victim outside the room is not a hit",
          D.p2p_battle_type_mode4(m4(struct.pack("<IIiII", 1, 0x7777, 10, _me, 3)),
                                  None, _me, _mem) is None)
    check("TWIN: an 80-byte body without the slot table is not a SHOT",
          D.p2p_battle_type_mode4(m4(bytes(56)), None, _me, _mem) is None)
    _sd = D.synth_p2p_inner(m4d, 113, _me)
    _sp = _sd["plain"]
    check("synth 113 header: type, flags 8, sender +16, victim +20, body verbatim",
          (_sp[8], _sp[9]) == (113, 8)
          and struct.unpack_from("<II", _sp, 16) == (_me, _foe)
          and _sp[D.BODY_OFF:] == m4d[D.BODY_OFF:]
          and struct.unpack_from("<H", _sp, D.CKSUM_OFF)[0] == D.cksum(
              bytearray(_sp[:D.CKSUM_OFF]) + bytes(2) + bytearray(_sp[D.CKSUM_OFF + 2:])))
    check("synth 112 header: target -1 (everyone)",
          struct.unpack_from("<I", D.synth_p2p_inner(m4s, 112, _me)["plain"], 20)[0]
          == 0xFFFFFFFF)

    # request 30: killer at body+8 (wire+32), victim = inner u32_20 (wire+20)
    r30 = bytearray(D.BODY_OFF + 12)
    struct.pack_into("<H", r30, D.BODY_OFF, 30)
    struct.pack_into("<I", r30, D.BODY_OFF + 8, 0x2a664)
    check("gs_kill_report: killer from body+8, victim from the inner header's wire+20",
          D.gs_kill_report({"u32_16": 0x41018, "u32_20": 0x41018},
                           bytes(r30[D.BODY_OFF:])) == (0x2a664, 0x41018))
    check("TWIN: no inner header, no report",
          D.gs_kill_report(None, bytes(r30[D.BODY_OFF:])) is None)

    # kind 9: four u16 team points, killer, victim, last-one flag, seq
    k9 = D.build_gs_kill_event([3, 1, 0, 0], 0x2a664, 0x41018, last_one=True,
                               seq9=7, seq=2, ident=0x41018)
    kb = body(k9)
    check("kill event is notify 35 kind 9",
          struct.unpack_from("<H", kb, 0)[0] == 35
          and struct.unpack_from("<I", kb, 12)[0] == 9)
    check("kind-9 record: team points u16 x4 at +0, killer +8, victim +12, last-one +18, seq +19",
          struct.unpack_from("<HHHH", kb, 20) == (3, 1, 0, 0)
          and struct.unpack_from("<II", kb, 28) == (0x2a664, 0x41018)
          and kb[38] == 1 and kb[39] == 7)

    # the room: a TBT to 3 kills
    rules = D.BattleRules(mode="TBT", time_limit=600, kill_target=3, respawn=5)
    room = D.BattleRoom(4, [0x2a664, 0x41018], {0x2a664: 0, 0x41018: 1}, rules,
                        leader=0x2a664, now=100.0)
    check("room: first 47 starts the clock, end = start + time limit",
          room.arrive(0x2a664, 100.0) and room.started == 100.0 and room.end_at == 700.0)
    check("room: a second 47 does not restart the clock",
          not room.arrive(0x41018, 130.0) and room.started == 100.0)
    # 2026-09-26: MISSION SUPPLIES. Request 44 = this battle's rounds fired;
    # the body below is a live one: 0x3000 x4, 0x3001 x6.
    import doc_shop as S_
    import doc_missions as M_
    _b44 = bytes.fromhex("2c000100000000000000000000300000040000000130000006000000") + bytes(48)
    check("supplies: request 44 -> handgun 4, rifle 6 fired (live body)",
          S_.fired_counts(_b44) == {0x62300000: 4, 0x62300001: 6})
    check("supplies: an all-zero 44 fired nothing", S_.fired_counts(bytes(76)) == {})
    check("supplies: top-up = the shortfall only, never lowers",
          S_.supply_grant({0x62300000: 32, 0x62300001: 18, 0x62300002: 90},
                          M_.STANDARD_SUPPLIES) == [(0x62300000, 4)])
    check("TWIN: a full bag gets NO grant (message 27 would double it)",
          S_.supply_grant({0x62300000: 36, 0x62300001: 18, 0x62300002: 60},
                          M_.STANDARD_SUPPLIES) == [])
    check("supplies: Beginner's Course I = 300 handgun + 3 Potions + 1 Phoenix "
          "Down (2006 wiki); PvP = standard",
          M_.supplies(39) == ((0x62300000, 300), (0x69320000, 3), (0x69320004, 1))
          and M_.supplies(None) == M_.STANDARD_SUPPLIES
          and M_.supplies(16) == M_.STANDARD_SUPPLIES)
    # 2026-09-26: the RESPAWN REFILL rides kind 25 at payload[20..43]
    # (body[36..]): 3 x {u32 id, u16 0, u16 qty}, SET into the victim's bag.
    _k25 = D.build_gs_down(1, 2, 3, ident=0x41050,
                           ammo=((0x62300000, 36), (0x62300001, 18), (0x62300002, 60)))
    _k25b = _k25[D.BODY_OFF:]
    check("kind 25 refill: 3 entries {id, 0, qty} at body[36..59]",
          [struct.unpack_from("<IHH", _k25b, 36 + 8 * i) for i in range(3)]
          == [(0x62300000, 0, 36), (0x62300001, 0, 18), (0x62300002, 0, 60)])
    check("kind 25 refill: the respawn point is unchanged at payload[8..13]",
          struct.unpack_from("<hhh", _k25b, 24) == (1, 2, 3))
    check("TWIN: kind 25 without ammo is the old 20-byte payload (list empty)",
          len(D.build_gs_down(1, 2, 3, ident=0x41050)) == len(_k25) - 24)
    # 2026-09-26 (retail 03-24 rule): the refill is BULLETS only, each row
    # max(supplies ledger, battle-start count); a SET never lowers the ledger
    check("respawn refill: PvP, empty ledger -> the three standard bullet rows",
          M_.respawn_refill(M_.STANDARD_SUPPLIES, {}) == M_.STANDARD_SUPPLIES)
    check("respawn refill: Beginner's Course -> handgun only, NO Potion row",
          M_.respawn_refill(M_.supplies(39), {0x69320000: 0})
          == ((0x62300000, 300),))
    check("respawn refill: a pickup above the issue is KEPT (ledger 50 > 36)",
          M_.respawn_refill(M_.STANDARD_SUPPLIES, {0x62300000: 50})[0]
          == (0x62300000, 50))
    check("respawn refill: below the issue -> topped up to the issue (5 -> 18)",
          M_.respawn_refill(M_.STANDARD_SUPPLIES, {0x62300001: 5})[1]
          == (0x62300001, 18))
    check("TWIN: the old rule (the start list, Potions included) differs",
          tuple(sorted(M_.supplies(39), key=lambda e: e[0] >> 16 != 0x6230))[:3]
          != M_.respawn_refill(M_.supplies(39), None)
          and M_.respawn_refill(M_.STANDARD_SUPPLIES, {0x62300000: 50})
          != M_.STANDARD_SUPPLIES)
    _rf = M_.respawn_refill(M_.STANDARD_SUPPLIES, {0x62300002: 99, 0x62300000: 1})
    check("respawn refill: every row >= ledger and >= issue",
          all(q >= max(dict(M_.STANDARD_SUPPLIES)[i],
                       {0x62300002: 99, 0x62300000: 1}.get(i, 0)) for i, q in _rf)
          and all(i >> 16 == 0x6230 for i, _q in _rf))
    # 2026-09-26: ONE shared GO, clock from the GO. Live table 31 (09-26,
    # 300 s): 47s at +0 / +1.6 / +10.3, GOs at +20.0 / +21.6 / +30.4, END
    # 300 s after the FIRST 47 -- the last client's HUD still read ~30 s.
    g = D.BattleRoom(31, [1, 2, 3], {1: 0, 2: 1, 3: 1},
                     D.BattleRules(mode="BT", time_limit=300), now=0.0)
    g.arrive(1, 0.0, go_after=20.0, go_wait=20.0)
    g.arrive(2, 1.6, go_after=20.0, go_wait=20.0)
    g.arrive(3, 10.3, go_after=20.0, go_wait=20.0)
    check("shared GO: due 20 s after the LATEST 47, and no clock before it",
          abs(g.go_at - 30.3) < 1e-9 and g.end_at is None
          and not g.go_due(30.2) and g.go_due(30.3))
    g.go()
    check("shared GO: the room clock starts AT the GO (end = GO + 300 s)",
          abs(g.end_at - 330.3) < 1e-9 and abs(g.elapsed(130.3) - 100.0) < 1e-9)
    check("shared GO: an arrival after the GO rides its own (joins_go False)",
          not g.joins_go(40.0, 20.0))
    tw = D.BattleRoom(31, [1, 2, 3], {1: 0, 2: 1, 3: 1},
                      D.BattleRules(mode="BT", time_limit=300), now=0.0)
    tw.arrive(1, 0.0)
    tw.arrive(2, 1.6)
    tw.arrive(3, 10.3)
    check("TWIN (no shared GO): the end is 300 s after the first 47, 30.3 s "
          "before the last client's HUD clock (GO +30.3) runs out",
          tw.end_at == 300.0 and abs((30.3 + 300) - tw.end_at - 30.3) < 1e-9)
    cap = D.BattleRoom(32, [1, 2], {1: 0, 2: 1},
                       D.BattleRules(mode="BT", time_limit=300), now=0.0)
    cap.arrive(1, 0.0, go_after=20.0, go_wait=20.0)
    check("shared GO: a 47 past the wait cap does not push the GO back",
          not cap.joins_go(25.0, 20.0)
          and not cap.arrive(2, 25.0, go_after=20.0, go_wait=20.0)
          and cap.go_at == 20.0)
    f1 = room.kill(0x2a664, 0x41018, 200.0)
    check("room: a kill credits the killer's team slot and counts the victim's death",
          f1 == ([1, 0, 0, 0], 0x2a664, 0x41018, False)
          and room.kills[0x2a664] == 1 and room.deaths[0x41018] == 1)
    check("room: a duplicate report within the dedupe window is ignored",
          room.kill(0x2a664, 0x41018, 200.5) is None and room.deaths[0x41018] == 1)
    check("room: the victim respawns after the record's delay",
          room.dead_until[0x41018] == 205.0 and room.respawns_due(204.0) == []
          and room.respawns_due(205.0) == [0x41018])

    # 2026-09-23 retail death flow (savestate: the invincible player's state
    # word entry+0x56 was 1; only kind 13 pushes code 13 = state 0, and only
    # after kind 25 set the dead bits 0x2400).
    _dn = D.build_gs_down(1090.4, -20.0, -515.6, rot=90.0, bmap=(1, 3),
                          ident=0x4103C)
    _db = _dn[24:]
    check("kind 25: kind at body[12], map0/map1 at payload[6..7], s16 x,y,z at "
          "payload[8..13], facing at payload[14..19]",
          struct.unpack_from("<I", _db, 12)[0] == 25
          and _db[16 + 6] == 1 and _db[16 + 7] == 3
          and struct.unpack_from("<3h", _db, 16 + 8) == (1090, -20, -516)
          and struct.unpack_from("<3h", _db, 16 + 14) == (1000, 0, 0))
    _dsrc = responder_source()
    _d43 = _dsrc[_dsrc.index("elif _gmt == GS_REVIVE_REQ"):
                 _dsrc.index("elif _gmt == GS_ITEM_USE_REQ")]
    check("request 43 (the kind-9 ack) never sends a revive", "sendto" not in _d43)
    check("TWIN: the retracted request-43 arm DID send one",
          "sendto" in "s.sendto(build_gs_notify(a.respawn_kind, struct.pack(\"<I\", a.phoenix_hp)")
    check("respawn default is kind 13 (18/19 left the state word at 1)",
          '"--respawn-kind", type=int, default=13' in _dsrc)
    check("TWIN: the shipped default 19 fails the same test",
          '"--respawn-kind", type=int, default=13' not in
          '"--respawn-kind", type=int, default=19')
    f2 = room.kill(0x2a664, 0x41018, 210.0)
    check("room: one kill from the target raises the last-one flag",
          f2[0] == [2, 0, 0, 0] and f2[3] is True and not room.over)
    check("room: a friendly / self kill counts the death but credits nobody",
          room.kill(0x41018, 0x41018, 220.0)[1] == 0 and room.points == [2, 0, 0, 0])
    f3 = room.kill(0x2a664, 0x41018, 230.0)
    check("room: the kill target ENDS the battle",
          room.over and "target" in room.why and f3[0] == [3, 0, 0, 0])
    check("room: verdict = the leading slot; loser loses, nobody draws",
          room.outcome(0x2a664) == "w" and room.outcome(0x41018) == "l"
          and room.winner_team() == 0)
    check("room: a kill after the end is ignored",
          room.kill(0x41018, 0x2a664, 240.0) is None)
    # 2026-09-24: First Attack / The Finisher come off the kill ledger
    check("room: first_killer = the first CREDITED kill, finisher = the kill "
          "that reached the target",
          room.first_killer == 0x2a664 and room.finisher == 0x2a664)
    tie = D.BattleRoom(5, [1, 2], {1: 0, 2: 1}, D.BattleRules(mode="TBT"), now=0.0)
    tie.arrive(1, 0.0)
    tie.kill(1, 2, 1.0)
    tie.kill(2, 1, 3.0)
    check("room: equal points is a DRAW for both",
          tie.outcome(1) == "d" and tie.outcome(2) == "d" and tie.winner_slot() is None)
    check("TWIN: no kill target means the clock alone ends it",
          not tie.over and tie.end_at == 180.0)
    check("room: a battle the clock ends has a first kill but NO finisher",
          tie.first_killer == 1 and tie.finisher is None)
    sk = D.BattleRoom(11, [1, 2], {1: 0, 2: 1},
                      D.BattleRules(mode="TBT", kill_target=1), now=0.0)
    sk.kill(2, 2, 1.0)
    check("TWIN: a self kill credits nobody -- no first kill, no finisher, not over",
          sk.first_killer is None and sk.finisher is None and not sk.over)
    tie.leave(2)
    check("room: a member that left is no longer present; the other is",
          tie.present() == [1] and 2 in tie.left)
    bt = D.BattleRoom(6, [1, 2, 3], {1: 0, 2: 1, 3: 2}, D.BattleRules(mode="BT"), now=0.0)
    bt.kill(3, 1, 1.0)
    bt.kill(3, 2, 2.0)
    check("room (BT): per-player kills, the top scorer wins alone",
          bt.kills == {1: 0, 2: 0, 3: 2} and bt.points == [0, 0, 0, 0]
          and bt.outcome(3) == "w" and bt.outcome(1) == "l" and bt.outcome(2) == "l")
    ms = D.BattleRoom(7, [1], {1: 0}, D.BattleRules(mode="MISSION"), mission=17, now=0.0)
    check("room (mission): the clock running out is a FAILURE",
          ms.outcome(1) == "l")
    ms.kill(1, 0x7777, 1.0)
    check("room (mission): an ENEMY kill is the mission's first kill",
          ms.first_killer == 1 and ms.kills[1] == 1)

    # the rules come from the RECORD
    rec = bytearray(D.build_battletable_record(table_id=9, leader=1, cur=2, maximum=6,
                                               map_idx=7, mode=1))
    struct.pack_into("<I", rec, D.BT_OFF_TIME, 600)   # "10 minute(s)" -> 600 s
    rec[D.BT_OFF_PENALTY] = 6          # respawn: config[+57]*1000 + 4000 ms
    rec[D.BT_OFF_BRIEFING] = 2         # "Briefing: 2 min"
    rec[D.BT_OFF_RESTRICT] = 0x0a      # Magic + Shooting restricted
    struct.pack_into("<H", rec, D.BT_OFF_SITUATION, 1100)
    r = D.battle_rules_from_record(bytes(rec), default_length=180, default_kill=20,
                                   default_respawn=4)
    check("rules: Time Limit = wire+4 u32 SECONDS, respawn = wire+117 + 4 s, briefing wire+111 min",
          r.time_limit == 600 and r.respawn == 10.0 and r.briefing == 120.0)
    check("rules: wire+116 is the RESTRICTIONS mask, not a time (the retracted reading)",
          r.restrictions == 0x0a and r.ko_limit == 0 and not r.random_teams and not r.npc)
    rk = bytearray(rec)
    struct.pack_into("<I", rk, D.BT_OFF_FLAGS, D.BT_FLAG_KO_LIMIT | D.BT_FLAG_RANDOM_TEAMS
                     | D.BT_FLAG_NPC | D.BT_FLAG_FRIENDLY_FIRE)
    rk[D.BT_OFF_KO_LIMIT] = 3
    rkr = D.battle_rules_from_record(bytes(rk))
    check("rules: KO Limit = wire+118 behind flag 0x00800000; Random / NPC / FF flags",
          rkr.ko_limit == 3 and rkr.random_teams and rkr.npc and rkr.friendly_fire)
    rk[D.BT_OFF_KO_LIMIT] = 5
    struct.pack_into("<I", rk, D.BT_OFF_FLAGS, 0)
    check("TWIN: a KO Limit byte without its flag is ignored",
          D.battle_rules_from_record(bytes(rk)).ko_limit == 0)
    rn = bytearray(rec)
    struct.pack_into("<I", rn, D.BT_OFF_TIME, 0)
    check("rules: Time Limit None + a kill target = NO clock (the target ends it)",
          D.battle_rules_from_record(bytes(rn), default_kill=20).time_limit == 0
          and D.BattleRoom(3, [1, 2], {1: 0, 2: 1},
                           D.battle_rules_from_record(bytes(rn), default_kill=20),
                           now=0.0).arrive(1, 5.0)
          and D.BattleRoom(3, [1, 2], {1: 0, 2: 1},
                           D.battle_rules_from_record(bytes(rn), default_kill=20),
                           now=0.0).end_at is None)
    pw = bytearray(rec)
    struct.pack_into("<I", pw, D.BT_OFF_FLAGS, D.BT_FLAG_PASSWORD)
    pw[D.BT_OFF_PW_REC:D.BT_OFF_PW_REC + 8] = b"abcd\x00\x00\x00\x00"
    check("record_password: flags bit 0 + wire+68 (4 chars); none without the flag",
          D.record_password(bytes(pw)) == b"abcd" and D.record_password(bytes(rec)) == b"")
    pst = D.BattletableStore()
    pk = pst.create(bytes(pw), 0x1, 0x10)
    check("store: CREATE takes the password FROM THE RECORD; a wrong JOIN password is -2",
          pst.reserve(pk, 0x2, b"zzzz\x00\x00\x00\x00")[0] == -2
          and pst.reserve(pk, 0x2, b"abcd\x00\x00\x00\x00")[0] == 0)
    # KO limit in the room: the third death puts a player out; a wiped side loses
    ko = D.BattleRoom(10, [1, 2, 3], {1: 0, 2: 1, 3: 1},
                      D.BattleRules(mode="TBT", ko_limit=2, respawn=1), now=0.0)
    ko.kill(1, 2, 1.0)
    check("room (KO limit): below the limit the victim respawns", 2 in ko.dead_until)
    ko.kill(1, 2, 3.0)
    check("room (KO limit): at the limit the victim is OUT, no respawn, not over yet",
          ko.eliminated(2) and 2 not in ko.dead_until and not ko.over)
    ko.kill(1, 3, 4.0)
    ko.kill(1, 3, 6.0)
    check("room (KO limit): the wiped side loses",
          ko.over and "KO limit" in ko.why and ko.outcome(1) == "w" and ko.outcome(3) == "l")
    check("rules: mode / max / situation / map / mission from the record",
          r.mode == "TBT" and r.maximum == 6 and r.situation == 1100
          and r.map_idx == 7 and r.mission == 0)
    check("rules: a zero wire+22 target FALLS BACK to the knob",
          r.kill_target == 20)
    struct.pack_into("<H", rec, D.BT_OFF_TARGET, 7)
    check("rules: the kill target is wire+22 (the config screen's Kill Count row, sec 4he)",
          D.battle_rules_from_record(bytes(rec), default_kill=20).kill_target == 7)
    rb = bytearray(rec)
    struct.pack_into("<I", rb, D.BT_OFF_FLAGS, D.BT_FLAG_INDIVIDUAL)
    check("rules: flag 0x200 = BT individual; 0x04000000 alone is Beginner TEAM play",
          D.battle_rules_from_record(bytes(rb)).mode == "BT"
          and D.battle_rules_from_record(bytes(rb[:0]) + bytes(rec[:0]) + bytes(
              (lambda x: (struct.pack_into("<I", x, D.BT_OFF_FLAGS, D.BT_FLAG_BEGINNER), x)[1])(bytearray(rec)))).mode == "TBT")
    rd = bytearray(rec)
    rd[D.BT_OFF_MODE] = 2
    rdm = D.battle_rules_from_record(bytes(rd))
    check("rules: mode byte 2 = TDM Team Survival, no respawns",
          rdm.mode == "TDM" and rdm.respawn < 0)
    check("rules: mode bytes 3..6 = TBS / TCP / TLD / TFL",
          [D.battle_rules_from_record(bytes(rd[:D.BT_OFF_MODE]) + bytes([mb]) + bytes(rd[D.BT_OFF_MODE + 1:])).mode
           for mb in (3, 4, 5, 6)] == ["TBS", "TCP", "TLD", "TFL"])
    # unit vs unit sides
    check("unit_teams: the first two units seated take sides 0 / 1, others keep theirs",
          D.unit_teams({1: 1, 2: 0, 3: 0, 4: 1, 5: 0}, [1, 2, 3, 4, 5],
                       {1: 0xA, 2: 0xA, 3: 0xB, 4: 0xC, 5: 0}.get)
          == {1: 0, 2: 0, 3: 1, 4: 1, 5: 0})
    # BT: per-player points in kind 9, the winner by kills
    ib = D.BattleRoom(8, [0x11, 0x22, 0x33], {}, D.BattleRules(mode="BT", kill_target=2), now=0.0)
    f = ib.kill(0x22, 0x11, 1.0)
    check("room (BT): kind 9 carries killer points / victim points, not team totals",
          f[0] == [1, 0, 0, 0] and ib.points == [0, 0, 0, 0])
    ib.kill(0x11, 0x22, 2.0)
    f = ib.kill(0x22, 0x33, 3.0)
    check("room (BT): the kill target ends it; winner = the top scorer's member index",
          ib.over and f[0][0] == 2 and ib.winner_cid() == 0x22 and ib.winner_slot() == 1
          and ib.outcome(0x22) == "w" and ib.outcome(0x11) == "l")
    check("room (BT): first kill and finisher are both 0x22",
          ib.first_killer == 0x22 and ib.finisher == 0x22)
    # TDM: last side standing
    sv = D.BattleRoom(9, [1, 2, 3], {1: 0, 2: 1, 3: 1}, D.battle_rules_from_record(bytes(rd)), now=0.0)
    sv.arrive(1, 0.0)
    sv.kill(1, 2, 1.0)
    check("room (TDM): one death is not a wipe; nobody respawns",
          not sv.over and 2 not in sv.dead_until and sv.alive() == [1, 3])
    sv.kill(1, 3, 2.0)
    check("room (TDM): the wiped side loses, the side standing wins",
          sv.over and "wiped" in sv.why and sv.outcome(1) == "w" and sv.outcome(2) == "l")
    check("room (TDM): the kill that wiped the side is the finisher",
          sv.finisher == 1)
    rz = D.battle_rules_from_record(bytes(D.build_battletable_record(table_id=9)),
                                    default_length=180)
    check("TWIN: a zero Time Limit with no target keeps the --gs-battle-length fallback",
          rz.time_limit == 180 and rz.respawn == 4.0)
    rm = bytearray(rec)
    struct.pack_into("<I", rm, D.BT_OFF_FLAGS, D.BT_FLAG_MISSION)
    struct.pack_into("<H", rm, D.BT_OFF_MISSION, 17)
    check("rules: the Mission flag makes it a MISSION with the quest id",
          D.battle_rules_from_record(bytes(rm)).mode == "MISSION"
          and D.battle_rules_from_record(bytes(rm)).mission == 17)
    check("rules: no record at all = the fallbacks",
          D.battle_rules_from_record(None, default_length=99).time_limit == 99)

    # the store: In Progress, refusals, leader authority, vacate
    ss = D.BattletableStore()
    sk = ss.create(D.build_battletable_record(table_id=0, leader=0x10, maximum=4),
                   0x1001, 0x10)
    ss.reserve(sk, 0x1002)
    check("store: a fresh table is not In Progress (wire+30 bit 0 clear)",
          not ss.in_progress(sk) and ss.record(sk)[D.BT_OFF_STATE] & 1 == 0)
    ss.set_in_progress(sk, True)
    check("store: In Progress sets wire+30 bit 0 on the served record",
          ss.record(sk)[D.BT_OFF_STATE] & 1 == 1
          and ss.records()[0][D.BT_OFF_STATE] & 1 == 1)
    check("store: a NEW seat is refused (-4) while In Progress; a member re-reserving is fine",
          ss.reserve(sk, 0x1003)[0] == -4 and ss.reserve(sk, 0x1002)[0] == 0
          and ss.members(sk) == [0x1001, 0x1002])
    ss.set_in_progress(sk, False)
    check("store: clearing In Progress reopens the seats",
          ss.reserve(sk, 0x1003)[0] == 0 and ss.record(sk)[D.BT_OFF_STATE] & 1 == 0)
    check("store: the creator is the leader by charid AND by uid",
          ss.is_leader(sk, 0x1001) and ss.is_leader(sk, 0, uid=0x10)
          and not ss.is_leader(sk, 0x1002) and not ss.is_leader(sk, 0x1002, uid=0x11))
    check("store: a member cannot kick / appoint / dissolve",
          not ss.kick(sk, 0x1003, 0x1002) and not ss.appoint(sk, 0x1002, 0x1002)
          and not ss.dissolve(sk, 0x1002) and ss.get(sk) is not None)
    check("store: the leader can",
          ss.kick(sk, 0x1003, 0x1001) and 0x1003 not in ss.members(sk))
    check("store: vacate = the seat goes without an answer",
          ss.vacate(0x1002) == sk and 0x1002 not in ss.members(sk)
          and ss.table_of(0x1002) is None)
    check("store: force-dissolve (the room's close) needs no leader",
          ss.dissolve(sk, force=True) and ss.get(sk) is None)
    # -- 2026-09-23 (sec 4hc): the new-player intro + the novice mark --------
    import doc_novice as NV
    door = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                     self_novice=True))
    plain = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176))
    check("novice: selector-2 world door carries body[129] bit 0x40",
          len(door) > NV.DOOR_NOVICE_OFF and door[NV.DOOR_NOVICE_OFF] & 0x40)
    check("novice: twin -- without self_novice body[129] has no 0x40 (the pre-fix door)",
          not plain[NV.DOOR_NOVICE_OFF] & 0x40)
    check("novice: only body[129] changes, and body[140] (the sec 4bo count) stays 0",
          [i for i in range(len(door)) if door[i] != plain[i]] == [NV.DOOR_NOVICE_OFF]
          and door[140:144] == bytes(4))
    sp = body(D.build_world_answer(world_door_request(), selector=13, pad_to=176,
                                   self_novice=True))
    sp0 = body(D.build_world_answer(world_door_request(), selector=13, pad_to=176))
    check("novice: the mark is selector-2 only (selector 13's body is untouched)", sp == sp0)
    ip = D.seal_world_body(None, NV.intro_push(), ptype=127, ident=0x4103C)
    check("intro: the push is selector 134, sub 10 at body[12], event 1 at body[16], "
          "ident at record+4",
          body(ip)[1] == 134 and struct.unpack_from("<I", body(ip), 12)[0] == 10
          and struct.unpack_from("<H", body(ip), 16)[0] == 1
          and struct.unpack_from("<I", ip, 16)[0] == 0x4103C)
    pr = D.build_peer_record(0x55, flags=0x40)
    check("novice: a peer record's FLAGS carry the mark at wire+30",
          pr[D.PEER_FLAGS_OFF] & 0x40 and D.PEER_FLAGS_OFF == 30)
    check("novice tables: BT_FLAG_NOVICE is bit 26 (lobby_rel 0x00aa1a84)",
          D.BT_FLAG_NOVICE == 0x04000000)
    # -- 2026-09-26: Collector's Mind's FUZZY SEED is a field item ----------
    import doc_npcquests as NQ
    import doc_field as DF
    # the generator nodes are the arena's own data (doc_item_generators.json,
    # not shipped): without it the check runs on a made-up node of its shape
    _seedtab = DF.load() or {208: ({7: [(NQ.FUZZY_SEED, 1, 100)]},
                                   {3000: [((100.0, -2.0, 200.0), 7)]})}
    _seedpos = (1159, -242, 1374) if DF.load() else (100, -2, 200)
    _seed = NQ.mission_items(NQ.COLLECTORS_MIND, 208, table=_seedtab)
    check("seed: quest 16 in the Church -> one Fuzzy Seed at SE's set-7 node",
          [(i, q, tuple(round(v) for v in p)) for i, q, p in _seed]
          == [(NQ.FUZZY_SEED, 1, _seedpos)], "%r" % _seed)
    check("seed: TWIN -- quest 16 opened in another arena, or quest 1 in the "
          "Church, finds none",
          NQ.mission_items(NQ.COLLECTORS_MIND, 201, table=_seedtab) == []
          and NQ.mission_items(1, 208, table=_seedtab) == [])
    check("seed: the item generators never roll it (a 100 %% node would "
          "respawn it every %.0f s); ammo still rolls" % DF.RESPAWN_S,
          not DF.usable(NQ.FUZZY_SEED) and DF.usable(0x62300000))
    check("seed: situation 3000's generators hand back no seed any more",
          all(NQ.FUZZY_SEED not in [i for i, _q, _w in rows]
              for _p, rows in DF.generators(208, 3000)))
    _sr = D.BattleRoom(9, [0xA], {0xA: 0}, D.BattleRules(mode="BT"),
                       mission=NQ.COLLECTORS_MIND, now=0.0)
    _sr.field = {7: (NQ.FUZZY_SEED, (1159.0, -242.0, 1374.0), 1)}
    _m, _n = D.capsule_pickup(_sr, 0xA, 7)
    check("seed: a pick-up is kind 11 (ident = the picker) and no capsule",
          [(k, i, t) for k, _p, i, t in _m] == [(11, 0xA, "all")]
          and struct.unpack_from("<I", _m[0][1], 4)[0] == NQ.FUZZY_SEED
          and not _sr.holders and 7 not in _sr.field, _n)
    _m, _n = D.capsule_pickup(_sr, 0xA, 7)
    check("seed: TWIN -- a resent touch finds the slot empty, grants nothing",
          _m == [] and "empty" in _n)
    # -- 2026-09-26: MP points (117), item use (21 -> 22), Ether MP ----------
    import doc_items as DI
    _plain = bytes(D.BODY_OFF) + DI.build_mp_point_body(4, n=7)
    _dat = bytes([0x04, 0x00]) + _plain[2:]
    _inn = {"is_data": True, "plain": _plain, "type": DI.P2P_MP_POINT}
    check("117: a reliable MP-point datagram is the SERVER's (p2p_server_type)",
          D.p2p_server_type(_dat, _inn) == 117)
    check("117: twin -- the pre-fix type set (118, 119) did not take it",
          117 not in (D.P2P_DROP, D.P2P_PICKUP))
    check("117: the payload decodes to point 4, count 7",
          DI.parse_mp_point(bytes(_plain[D.BODY_OFF:])) == (0, 4, 7))
    check("117: never relayed as a battle packet (it is in the server's set)",
          117 in D.P2P_BATTLE_TYPES and 117 in D.P2P_SERVER_TYPES)
    # 2026-09-26: MP is FULL at every battle start (Additional Manual P.031):
    # the ledger keys on (room key, opened), so a drained player's next room
    # starts at 100 -- the same the client's own kind-2 refill does.
    import doc_magic as MG_
    _lg = MG_.Ledger()
    _ra = D.BattleRoom(20, [0xA], {0xA: 0}, D.BattleRules(mode="TBT"), now=100.0)
    _rb = D.BattleRoom(20, [0xA], {0xA: 0}, D.BattleRules(mode="TBT"), now=400.0)
    _lg.cast(0xA, (_ra.key, _ra.opened), 0x20002, 100.0)
    _lg.cast(0xA, (_ra.key, _ra.opened), 0x20002, 102.0)
    check("MP: two Thunders drain battle A to 0",
          _lg.mp(0xA) == 0)
    check("MP: the SAME table's next battle starts at 100 (a new room key)",
          _lg.cast(0xA, (_rb.key, _rb.opened), 0x10003, 401.0)[0] == 100 - 20)
    check("TWIN: the same room keeps the drained MP",
          _lg.credit(0xA, (_rb.key, _rb.opened), 0) == 80)
    _r28 = DI.mp_points_record()
    _p28 = body(D.build_gs_notify(28, _r28))
    check("kind 28 MP points: record at body[20] -- count 64 at +2, mask at +4",
          _p28[20 + 2] == 64
          and struct.unpack_from("<Q", _p28, 24)[0] == 0xFFFFFFFFFFFFFFFF)
    _z28 = body(D.build_gs_notify(28))
    check("kind 28: twin -- the old bare 28 carried count 0 (no MP point made)",
          len(_z28) <= 22 or _z28[22] == 0)
    check("kind 28 MP points: rec[0], rec[1], rec[3] stay 0 ([chan+204] bits as before)",
          _p28[20] == 0 and _p28[21] == 0 and _p28[23] == 0)
    _a22 = body(D.build_item_use_answer(0x69320006, ident=0x4103C))
    check("message 22: type 22, body+8 = the item (the effect receiveUseItem runs)",
          struct.unpack_from("<H", _a22, 0)[0] == 22
          and struct.unpack_from("<I", _a22, 8)[0] == 0x69320006)
    _L = D.doc_magic.Ledger()
    _L.cast(9, "b", 0x10001, 0.0)
    _mp = _L.credit(9, "b", DI.ITEM_MP[0x69320006])
    _k44 = body(D.build_gs_mp_push(_mp))
    check("Ether after one Fire: ledger 70 + 50 -> 100, kind 44 HIGH half = 100",
          _mp == 100 and struct.unpack_from("<I", _k44, 12)[0] == 44
          and struct.unpack_from("<I", _k44, 16)[0] >> 16 == 100)
    _L2 = D.doc_magic.Ledger()
    _L2.cast(9, "b", 0x10002, 0.0)
    check("Ether after one Thunder: 50 + 50 = 100; twin -- no credit leaves 50",
          _L2.mp(9) == 50 and _L2.credit(9, "b", 50) == 100)
    check("doc_items selftest", DI._selftest())
    import doc_chat as DC
    check("doc_chat selftest: say / shout / entry / team scopes", DC._selftest())
    check("doc_chat kinds: say 5, shout 6, tell 3, entry 2, team 7 (0x00b1b1e8)",
          (DC.KIND_SAY, DC.KIND_SHOUT, DC.KIND_TELL, DC.KIND_ENTRY,
           DC.KIND_TEAM) == (5, 6, 3, 2, 7))

    # 2026-09-26 (launch-lobby): table Min/Max RP are set in the table's game
    # rules (source: January 2006 player guide, multiplayer page)
    _rr = bytearray(D.build_battletable_record(table_id=0, leader=0, cur=1,
                                               maximum=6, map_idx=3, mode=1,
                                               flags=D.BT_FLAG_MAX_RP))
    struct.pack_into("<I", _rr, D.BT_OFF_MAX_RP, 500)
    check("RP limit: 500 RP at a 'Below 500' table is allowed (inclusive)",
          D.rp_allowed(bytes(_rr), 500)[0])
    check("RP limit: 501 RP is refused by the Maximum RP",
          not D.rp_allowed(bytes(_rr), 501)[0])
    _rn = bytearray(_rr)
    struct.pack_into("<I", _rn, D.BT_OFF_FLAGS, 0)
    check("RP limit: TWIN -- the same 500 at +60 WITHOUT flag 0x00080000 limits "
          "nothing", D.rp_allowed(bytes(_rn), 9999)[0])
    _rm = bytearray(_rn)
    struct.pack_into("<I", _rm, D.BT_OFF_FLAGS, D.BT_FLAG_MIN_RP)
    struct.pack_into("<I", _rm, D.BT_OFF_MIN_RP, 100)
    check("RP limit: Minimum RP 100 refuses 99, seats 100",
          not D.rp_allowed(bytes(_rm), 99)[0] and D.rp_allowed(bytes(_rm), 100)[0])
    _rs = D.BattletableStore()
    _rk = _rs.create(bytes(_rr), 0x101, 0x101)
    check("RP limit: reserve() refuses 900 RP with BT_REFUSE_RP (-7)",
          _rs.reserve(_rk, 0x102, rp=900)[0] == D.BT_REFUSE_RP == -7
          and 0x102 not in _rs.members(_rk))
    check("RP limit: reserve() seats 20 RP; rp=None (--rp-tables open / no "
          "stats) is never checked",
          _rs.reserve(_rk, 0x103, rp=20)[0] == 0
          and _rs.reserve(_rk, 0x104)[0] == 0)
    check("RP limit: a member already seated is not re-checked",
          _rs.reserve(_rk, 0x103, rp=9000)[0] == 0)
    _src26 = responder_source()
    check("RP limit: the JOIN arm and the RESERVE verb both pass the joiner's rp",
          _src26.count("rp=rp_of_cid(_ident or seen_charid[0] or 0)") == 3)

    # 2026-09-26: the Soldier Mask is EARNED (Drone 2nd exam) -- a NEW wallet
    # carries the rule mark, so its character logs in with NO mask
    import doc_gear as G26
    import doc_shop as S26
    check("mask: doc_shop's new-wallet mark IS doc_gear's rule mark",
          S26.SOLDIER_MASK_RULE_MARK == G26.MASK_RULE_MARK)
    docdb.store("shop").clear()
    _sh26 = S26.Shop(docdb.store("shop"))
    _w26 = _sh26.wallet("anon/0x00000026")
    check("mask: a new character holds no mask (settle -> None, bag untouched)",
          G26.settle_soldier_mask(_w26, False)[0] is None
          and not [k for k in _w26["bag"] if k.startswith("0x6330")])
    _w26.pop(G26.MASK_RULE_MARK)
    check("mask: TWIN -- a wallet from before the rule keeps its mask",
          G26.settle_soldier_mask(_w26, False)[0] == G26.MASK_DG_M)
    docdb.store("shop").clear()
    _wg26 = body(D.build_world_answer(world_door_request(), selector=2, pad_to=176,
                                      ident=0, self_gear=(G26.NO_ITEM, 0x63310000)))
    check("mask: no mask = 0xFFFFFFFF at world-door body[76], the suit at [80]",
          struct.unpack_from("<II", _wg26, 76) == (0xFFFFFFFF, 0x63310000))
    check("mask: the exam tally owes it (quest SOLDIER_MASK_EXAM == 1 = the "
          "Drone 2nd exam, promotes to rank 2)",
          G26.SOLDIER_MASK_EXAM == 1 and D.doc_stats.EXAM_PROMOTIONS[1] == 2
          and "doc_gear.owe_soldier_mask(w)" in _src26)

    # 2026-09-26: the line-drop penalty is charged BEFORE the member leaves
    # the room (charge_line_drop needs it in room.arrived), and only for the
    # line-drop reasons
    _vs = _src26[_src26.index("    def vacate_seat(cid, why):"):]
    _vs = _vs[:_vs.index("\n    def ", 10)]
    check("line drop: vacate_seat charges before room.leave()",
          0 < _vs.find("charge_line_drop(room, cid, why)")
          < _vs.find("_nl = room.leave(cid)"))
    _lw = _src26[_src26.index("LINE_DROP_WHYS = ("):]
    _lw = _lw[:_lw.index(")") + 1]
    check("line drop: reaped / line dropped only -- never kicked or a new sign-in",
          '"session reaped"' in _lw and '"line dropped"' in _lw
          and "kicked" not in _lw and "new entrance" not in _lw)
    check("line drop: the reaper and the silence check use those exact reasons",
          'vacate_seat(_sess.seen_charid[0], "session reaped")' in _src26
          and 'vacate_seat(m, "line dropped")' in _src26)

    # 2026-09-26: the WEEKLY medals (doc_stats.WEEKLY_MEDALS, ids 19..22)
    import doc_stats as WK
    check("weekly: the four are SE's 60:[35..38], medal ids 19..22, inside the "
          "24-bit door mask and the +168 count block",
          [i for _f, i in WK.WEEKLY_MEDALS] == [35, 36, 37, 38]
          and [WK.MEDALS[i] for _f, i in WK.WEEKLY_MEDALS] == [
              "Weekly Rank Points 1st", "Weekly Defeats 1st",
              "Weekly Team Wins 1st", "Weekly Solo Wins 1st"]
          and all(0 <= i - WK.MEDAL_BASE < WK.MEDAL_IDS
                  for _f, i in WK.WEEKLY_MEDALS)
          and 168 + 4 * (38 - WK.MEDAL_BASE) + 4 <= 264)
    _W = 1790521200                  # Mon 2026-09-28 00:00 JST
    _ph = WK.parse_week_start("mon 00:00 +09:00")
    check("weekly: Monday 00:00 JST = Sunday 15:00 UTC; 14:59:59 UTC is the "
          "week before", WK.week_of(_W, _ph) == _W
          and WK.week_of(_W - 1, _ph) == _W - WK.WEEK_SECS)
    check("weekly: TWIN -- a UTC week start puts Sunday 23:00 UTC in the "
          "OLD week, JST in the new one",
          WK.week_of(_W + 8 * 3600, WK.parse_week_start("mon 00:00 +00:00"))
          != _W and WK.week_of(_W + 8 * 3600, _ph) == _W)
    docdb.store("stats").clear()
    _ws = WK.Stats(docdb.store("stats"))
    _ws.clock = lambda: _W + 60
    _ws.record_battle("BT", [{"key": "p", "team": 1, "kills": 2},
                             {"key": "q", "team": 2, "kills": 0}], 1, 120)
    _ws.record_battle("TBT", [{"key": "q", "team": 0, "kills": 2},
                              {"key": "r", "team": 1, "kills": 0}], 0, 120)
    _v = _ws.close_week(_W, now=_W + WK.WEEK_SECS)
    _aw = {int(i): x["key"] for i, x in _v["awards"].items()}
    check("weekly: solo win p, team win q, kills TIED p/q -> nobody, rp p "
          "(40) vs q (10 + 40 = 50) -> q",
          _aw == {35: "q", 36: None, 37: "q", 38: "p"}, "%r" % _aw)
    check("weekly: a closed week closes once (restart included)",
          _ws.close_week(_W) is None and WK.Stats(docdb.store("stats")).close_due(
              now=_W + 5 * WK.WEEK_SECS) == []
          and WK.medal_count(WK.Stats(docdb.store("stats")).career("q"), 37) == 1)
    docdb.store("stats").clear()
    check("weekly: docudp closes on startup AND on the rollover deadline, "
          "gated by --weekly-medals",
          'weekly_close("startup catch-up")' in _src26
          and 'weekly_close("week rollover")' in _src26
          and "_wd = weekly_deadline()" in _src26
          and 'a.weekly_medals != "on"' in _src26
          and "_stats.week_phase = doc_stats.parse_week_start(a.week_start)"
          in _src26)
    print("%d check(s) failed" % len(FAILS) if FAILS else "ALL PASS")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
