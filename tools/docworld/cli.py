"""Talk back to Dirge of Cerberus on its world channel (UDP 55040).

DoC dials `kel-1001.pol.com:55040` and re-sends an 80-byte datagram until it
gives up.  Nothing has ever answered it, so the server->client direction is
entirely unknown.  This is the instrument for changing that: it binds the port,
logs every datagram, and sends back a candidate reply that you choose on the
command line -- so a hypothesis costs one restart, not a code change.

    python3 docudp.py                          # log only, send nothing
    python3 docudp.py --mode subtype --subtype 4 --lobby-probe advance   # THE FIX
    python3 docudp.py --mode echo              # bounce the packet straight back
    python3 docudp.py --once                   # answer one datagram, then idle

## Current state (2026-08-24): the lobby handshake is SOLVED

`--mode subtype --subtype 4 --lobby-probe advance` answers the entrance with the
subtype-4 redirect (drives the main connection to state 7) AND answers the
96-byte type-129 lobby packets with a mode-0 selector-2 reply that advances the
UDATA nest 1->2 (and the main connection 7->8).  Proven offline end-to-end
against kel's real parser + driver (measured offline against the client's own
parser); expect DoC to
leave CER-48103 and enter the Kerberos event stage (the next wall: `can't find
event data` -> CER-40000, real game/user-data).  See `build_lobby_advance`.

## Why the client's own logging is the oracle

The preview build narrates its own rejections.  `[KEL NET ENT]Drop packet bad
packet` means the datagram reached the packet handler and failed validation;
silence means it never got that far.  So the emulog, not this script, tells you
whether a candidate was any good.  Run PCSX2 with its console visible and watch
it while this runs.

## What is known about the wire format (client->server), all measured

    +0   u8    0x04
    +1   u8    0x01
    +2   u16LE total length (80 on every packet seen)
    +4   u32LE millisecond timestamp
    +8   16B   varies every packet; PROVENANCE UNKNOWN -- see below
    +24  52B   body; mostly identical across sessions, lightly transformed
    +76  u16   0x0200
    +78  2B    flag, only 0000 or 8080 observed

## What the client checks on receive (static RE of kel.pex, base 0x00280000)

1. `0x00585b28` -- the datagram must come from the peer it dialled.  Replying
   from this socket satisfies that for free; there is no token to forge.
2. `0x00585f50` -- reads a SUBTYPE byte at **packet+25** (i.e. body[1]) and
   accepts subtype 3 only in connection state 3, subtype 4 only in state 5.
3. Live savestates show the connection parks in **state 5** and stays there for
   the whole ~40 s window, so **subtype 4 is the one to aim at**.

## The honest unknown

The 16 bytes at +8 are not understood.  An earlier reading concluded they were
ciphertext from the codec at `0x00584888`; that was RETRACTED when live states
showed the key pointer `[0x005ee4a0]` null on a working connection.  They may be
a nonce, a digest, or something the receive path ignores entirely.  `--crypto`
exists precisely because we do not know: try each option and let the client say.

The per-selector details are in the docstrings of the build_* functions below.
"""
import argparse
import doc_novice
import doc_field
import doc_npc_spawn
import doc_npcquests
import doc_stats
import doc_shop
import doc_items
from . import arenadata, arenamaps, battleroom, briefingroom, charrecords, framing, gamemsg, tablerecords, worldchannel



def _week_start_arg(spec):
    try:
        doc_stats.parse_week_start(spec)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))
    return spec


#: what a store flag says when it is off; "on" (or anything else) turns it on
_STORE_OFF = ("", "off", "0", "no")


def store_on(value, flag, store):
    """True when a store flag (--chara-store, --shop, --stats, ...) turns its
    store on. The stores are PostgreSQL tables now (docdb.py), so the flag is
    on or off. A value that is neither is the path of the store's old JSON
    file: that still turns the store on, and the file is NOT read -- this says
    so once, with the command that imports it."""
    v = (value or "").strip()
    if v.lower() in _STORE_OFF:
        return False
    if v.lower() not in ("on", "1", "yes"):
        print("[docudp] %s %s: the %s store is in PostgreSQL now (docdb.py) and "
              "this file is not read. Import it once, into an empty store, with "
              "`python docdb.py import %s %s`." % (flag, v, store, store, v),
              flush=True)
    return True


def members_on(a):
    """--pol-members, or the old --accounts-db given any value (its path is
    not read: the core's accounts are in PostgreSQL)."""
    if a.pol_members == "on":
        return True
    if (a.accounts_db or "").strip():
        print("[docudp] --accounts-db %s: the core's accounts are in PostgreSQL "
              "now; this path is not read. Treated as --pol-members on."
              % a.accounts_db, flush=True)
        return True
    return False


def build_parser():
    """The command line: every flag of the responder, with its help text."""
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=framing.PORT)
    ap.add_argument("--mode", choices=["none", "echo", "subtype"], default="none",
                    help="what to send back (default: nothing, log only)")
    ap.add_argument("--subtype", type=int, default=4,
                    help="value for body[1]; 4 is accepted in state 5, 3 in state 3")
    ap.add_argument("--crypto", choices=["echo", "zero", "copyhdr"], default="echo",
                    help="what to put in the 16 unknown bytes at +8")
    ap.add_argument("--body-len", type=int, default=56,
                    help="body length; the client sends 56 (52 + 2 + 2)")
    ap.add_argument("--peer", default=None,
                    help="allowlist of source IPs to answer, comma/space separated "
                         "(default: answer whoever asks). sec 4fq: each IP gets "
                         "its OWN session, so two clients can share one match.")
    ap.add_argument("--type", type=int, default=128, dest="ptype",
                    help="packet+8, the message TYPE. 128 (0x80) is what the client "
                         "itself sends. Dispatch arms exist for 0,1,2,3,4,126,127,128,254,255.")
    ap.add_argument("--flags", type=int, default=0,
                    help="packet+9. bit 3 (0x08) makes the client look up an ID at "
                         "packet+16; leave clear unless you have a valid ID.")
    ap.add_argument("--mode-byte", type=int, default=0,
                    help="packet[1], the cipher selector. 0 = NO-OP (0x00584364), "
                         "1 = the mode the client itself uses. Default 0.")
    ap.add_argument("--no-cksum", action="store_true",
                    help="leave the checksum field zero -- the client will then REPORT "
                         "its own computed value, which validates our implementation")
    ap.add_argument("--lobby-ip", default="127.0.0.1",
                    help="address handed to the client in the subtype-4 body as the "
                         "LOBBY server (body+12). Empty string leaves the body zeroed.")
    ap.add_argument("--lobby-port", type=int, default=55040,
                    help="port for the same redirect (body+10)")
    ap.add_argument("--sweep", action="store_true",
                    help="step through the SWEEP table, one candidate per connection "
                         "burst, printing a banner so the Nth error code the tester "
                         "reports matches the Nth banner")
    ap.add_argument("--once", action="store_true",
                    help="send a reply to the first datagram only, then log-only")
    ap.add_argument("--save", default=None, help="directory to write datagrams into")
    ap.add_argument("--lobby-probe", choices=["off", "echo", "advance"], default="off",
                    help="how to answer the LOBBY packets (the 96-byte, type-129 shape) as "
                         "opposed to the 80-byte entrance. 'advance' (RECOMMENDED) sends the "
                         "mode-0 selector-2 reply PROVEN offline to flip the UDATA nest 1->2 "
                         "and the main connection 7->8: expect DoC to leave "
                         "CER-48103 and enter the Kerberos event stage. 'echo' bounces the "
                         "client's own 96-byte packet back (only elicits a CTRL-24, never "
                         "advances). The 80-byte entrance always gets the subtype-4 redirect. "
                         "Watch the emulog for the phase change, not this log.")
    ap.add_argument("--lobby-sustain-selector", type=int, default=8,
                    help="body[1] of the SUSTAIN reply, sent to every 96-byte type-129 "
                         "packet. 8 routes (via the inbound router's jump table, index "
                         "selector-4) to the state-6 handler 0x00587c10, which advances "
                         "the nest 6->2; it then self-advances 2->6, re-stamping the "
                         "liveness field the 10s watchdog watches. PROVEN offline against "
                         "a live state-6 savestate of the lobby (doc_state6_router.py). "
                         "0 disables (old selector-2-only behaviour).")
    ap.add_argument("--lobby-sel2-count", type=int, default=1,
                    help="if non-zero, ALSO send the selector-2 (1->2) advance reply to every "
                         "96-byte packet (in addition to the sustain reply). selector-2 is a "
                         "no-op at every state except state 1, so this is always safe and needs "
                         "no per-connection tracking. 0 disables selector-2 entirely.")
    ap.add_argument("--lobby-extra-selectors", default="",
                    help="comma-separated EXTRA response codes to send after the main "
                         "reply, e.g. 14.  THE LADDER (sec 4ao, each handler gated on a "
                         "specific nest state, so every one is a no-op unless the client "
                         "happens to be in its state -- VERIFIED offline against the "
                         "state-6 savestate: of 2,8,10,12,14,16,18,20,22,24 only 8 moves "
                         "a state-6 nest):\n"
                         "  code  state  handler     what it does\n"
                         "   8     6     0x00587c10  the CHARACTER LIST (see --lobby-chara-*)\n"
                         "  10     8     0x00587ee0  BARE ACK (sets state 2, no payload)\n"
                         "  12     7     0x00587e50  returns ONE record via [nest+0xE8]\n"
                         "  14     9     0x00587ef0  BARE ACK (sets state 2, no payload)\n"
                         "  16    10     0x00587e98  returns ONE record via [nest+0xE8]\n"
                         "  18/20/22/24  0x00587f00/f98/fa8/ff0\n"
                         "State 9 is the interesting one: its REQUEST 0x005888f8 packs a "
                         "character record into a type-13 message using the exact INVERSE "
                         "of the 0x0058ad30 list permute (buf+58 -> wire+85 ...), which is "
                         "what create-a-character looks like -- and it only wants code 14, "
                         "an empty ack.  CER-48104 is the charamake server timing out.\n"
                         "WARNING: each entry is one MORE datagram per inbound packet, and "
                         "flooding the client receive ring is what killed the ACK sweep "
                         "(sec 4ae: 5 extra -> 38 s, from a 75 s baseline).  Send ONE.")
    ap.add_argument("--extra-subtypes", default="",
                    help="FALSIFIED LIVE 2026-08-24 -- DO NOT USE without re-proving it. "
                         "Sending subtype 3 alongside 4 BROKE the entrance handshake: the "
                         "boot regressed from catch error = -47110(phase 3) to -1(phase 1), "
                         "never printed connected entrance server, and left [conn+0xD0] = -2 "
                         "with the nest never opened (state 0). The connection PASSES THROUGH "
                         "state 3 during the normal handshake, so a subtype-3 message arriving "
                         "then is accepted at the wrong moment and derails it. The argument "
                         "that each subtype is state-gated so both are safe was an ANALOGY to "
                         "the nest selectors -- those were verified as no-ops against a live "
                         "savestate; this never was. Verify offline before re-enabling. "
                         "comma-separated EXTRA subtypes to ALSO answer each non-lobby "
                         "(80-byte type-128) packet with, e.g. 3.  MEASURED (0x00585fc4): the "
                         "inbound dispatcher reads the subtype at [record+1] and accepts\n"
                         "  subtype 3  ONLY when [conn+0xD0] == 3  -> 0x00585d28\n"
                         "  subtype 4  ONLY when [conn+0xD0] == 5  -> 0x00585ec8\n"
                         "and IGNORES every other subtype outright.  The connection sits in "
                         "state 3/4 through the whole lobby phase (savestate: [main+0xD0]=3), "
                         "so the fixed subtype-4 redirect we have always sent is DISCARDED "
                         "there -- which is why the two 00 01 requests go unanswered and the "
                         "retry timer raises CER-48104.  Each subtype is state-gated inside "
                         "the client, so sending both is safe: the one that does not match "
                         "the current state is a no-op (same reasoning as the nest selectors).")
    ap.add_argument("--frag3", action="store_true",
                    help="answer the LOBBY requests (80-byte type-128 packets whose body "
                         "tail is 00 01) with a SUBTYPE-3 fragmented response: parts=1, "
                         "index=0, payload from body[8] (handler 0x00585d28). Those two "
                         "requests -- 00 01 33 c1 and 00 01 b3 44 -- are what currently go "
                         "unanswered until the retry timer raises CER-48104. The entrance "
                         "packets (tail 00 02) are NEVER touched, which is the difference "
                         "from --extra-subtypes (falsified, sec 4aw).")
    ap.add_argument("--frag3-servers", default="",
                    help="comma-separated ip:port entries to put in the subtype-3 "
                         "payload as 12-byte server-list records, e.g. "
                         "127.0.0.1:55040. Empty sends a fragment with ZERO entries, "
                         "which registers the fragment but copies nothing. Full form is "
                         "ip:port[:id[:tail[:area]]]; `area` defaults to --frag3-area.")
    ap.add_argument("--frag3-area", type=lambda v: int(v, 0), default=1,
                    help="entry+8, the AREA/tab id the Select Server screen filters "
                         "on (0x00AB4598). The client keeps its own area code in "
                         "[0x001B5658] -- a link-time constant, measured 1 -- and "
                         "DROPS every row whose area id is neither that nor 0xFFFF. "
                         "We sent 0 for the life of this service, which is why the "
                         "list was always empty. 1 = the default tab, 0xFFFF = the "
                         "'all areas' tab.")
    ap.add_argument("--no-chara-on-request", dest="chara_on_request",
                    action="store_false", default=True,
                    help="answer the client's selector-7 with the chara code-8 straight "
                         "away (the old behaviour) instead of holding it until the 00 01 "
                         "request. Holding is the default because answering early is "
                         "MEASURED to lose: savestate 15:41:32 shows [nest+8]=2 with the "
                         "armed high bit clear -- the code-8 arm's own signature, so it "
                         "WAS accepted -- while [nest+0xF4] stayed untouched and holds "
                         "byte-identical garbage across three boots. The client had not "
                         "pointed that field at the real buffer yet. Not answering parks "
                         "the nest at 6 (armed) and the watchdog budget [nest+4]=40000 is "
                         "~20 s, while the 00 01 request lands ~4 s later.")
    ap.add_argument("--frag3-hold-s", type=float, default=0.0,
                    help="INSTRUMENT, not a fix. RED FLAG: phase 3 only tolerates about "
                         "SIX SECONDS. Holding longer times the poll out -- [conn+0xD0] "
                         "goes negative and the boot dies with -47110(phase = 3) / "
                         "CER-48104. MEASURED twice (holds of 30 s and 20 s, boots 15:41 "
                         "and 15:53), and it kills the run BEFORE phase 4 ever reads the "
                         "buffer, so anything downstream of phase 3 goes untested. Keep "
                         "any hold under ~5 s. After the selector-7 chara burst, hold "
                         "back the frag3 answer to the 00 01 request for this many "
                         "seconds. That answer is what releases phase 3, so holding it "
                         "parks the client in the poll and leaves [nest+8] and "
                         "[nest+0xF4] readable for as long as you like. [nest+8]==2 means "
                         "our code-8 WAS accepted and the count is not where we think it "
                         "is; ==6 means it never reached the handler and the offline "
                         "harness -- which calls the parser and router directly and models "
                         "none of the socket path -- has been lying (the sec 4ax trap). "
                         "0 = off.")
    ap.add_argument("--chara-burst", type=int, default=6,
                    help="how many copies of the CHARA code-8 to send when the client "
                         "transmits SELECTOR 7 -- the 2->6 arm 0x005884d0, the only thing "
                         "that opens nest state 6 and therefore the only window in which "
                         "handler 0x00587c10 will write the character count. The first "
                         "acceptance drops the nest to 2, and boot 13:22 saw exactly ONE "
                         "selector-7 in the whole session, so a single reply that loses a "
                         "50 ms race costs the entire boot. A code-8 outside state 6 is a "
                         "proven no-op (an offline run of the client's own code (doc_code8_wire_proof) sweeps states "
                         "0..7), so the extra copies are free. 1 = old behaviour.")
    ap.add_argument("--chara-burst-ms", type=int, default=25,
                    help="spacing between the --chara-burst copies, in ms.")
    ap.add_argument("--no-nest-close-answer", dest="nest_close_answer",
                    action="store_false", default=True,
                    help="do NOT answer the nest's selector-3 CLOSE request with a "
                         "selector-4 reply. On by default, because phase 110 cannot "
                         "pass without it: phase 109 (main-conn vtable+36 = "
                         "0x00586910) calls the nest's vtable+220 = 0x00587a98, which "
                         "sends selector 3 and sets [nest+8] = 4; phase 110 polls "
                         "0x00587b40, which returns 1 only at [nest+8] == 0; and the "
                         "only writer of 0 from 4 is the classifier's selector-4 arm "
                         "0x00589690. PROVEN offline against a live nest -- "
                         "an offline run of the client's own code (doc_close_proof) -- including the control that "
                         "selector 4 is a strict no-op in states 0,1,2,3,5,6,7, so it "
                         "cannot derail anything earlier. (Unlike the subtype-3 case "
                         "of sec 4aw: state 4 is written ONLY by the close path, so it "
                         "is genuinely terminal, not transited on the healthy path.)")
    ap.add_argument("--nest-quiet-after-frag3", type=int, default=0,
                    help="after this many subtype-3 frag replies have been sent, STOP all "
                         "nest traffic (code-8 answers to 36-byte packets, the selector-2 and "
                         "selector-8 replies to 96-byte packets, and the keepalive). 0 = never. "
                         "WHY: phase 110 polls 0x00587b40, which returns 1 only when the NEST "
                         "state [nest+8] is ZERO -- it waits for the nest to CLOSE. Every code-8 "
                         "sets [nest+8]=2, so a chatty responder pins the nest open and phase 110 "
                         "times out with -47111 / CER-48103 (MEASURED, boot 12:30: reached phase "
                         "110, died 70 s later, cursor frozen). SUPERSEDED: silence is NOT the "
                         "answer -- the nest does not close on its own, it closes on an inbound "
                         "SELECTOR 4 (see --no-nest-close-answer). Keep this at 0. But the nest "
                         "replies are REQUIRED "
                         "earlier -- with them off from the start the client never issues the "
                         "00 01 list requests and dies at phase 1 (MEASURED, boot 12:35). So it is "
                         "a SEQUENCING problem: chatty until the list is answered, silent after. "
                         "The frag3 reply is the natural trigger -- phase 4 follows it within "
                         "milliseconds and phase 110 comes after that.")
    ap.add_argument("--frag3-server-id", type=lambda x: int(x, 0), default=0,
                    help="entry+0 of every server-list entry, the default when "
                         "--frag3-servers does not carry one. The Select Server "
                         "screen (KelStr group 29) has a NAME column and a "
                         "`Players Connected` column and we have only ever "
                         "written 0 here; a distinct value says which column "
                         "reads it (the 2026-09-05 audit J).")
    ap.add_argument("--frag3-server-tail", type=lambda x: int(x, 0), default=0,
                    help="entry+10 of every server-list entry -- the other "
                         "unidentified column. See --frag3-server-id.")
    ap.add_argument("--frag3-parts", type=int, default=1,
                    help="body[4..5], the TOTAL part count of the subtype-3 response.")
    ap.add_argument("--chara-store", default="",
                    help="on = the per-account character store (sec 4dq), the "
                         "doc_character table in PostgreSQL (POL_DATABASE_URL, "
                         "docdb.py). When on, REGISTER and DELETE PERSIST -- created "
                         "characters stick across reconnects, deletes take, and "
                         "each account (keyed by its entrance uid) sees its OWN "
                         "roster instead of the seeded --lobby-chara-* Quarrys. "
                         "Empty or off = the old fixed seeding. The path of the "
                         "old doc-characters.json also means on (the file is not "
                         "read; `python docdb.py import characters FILE`).")
    ap.add_argument("--account", default="",
                    help="key the --chara-store by THIS account (e.g. member:3) "
                         "instead of the entrance uid. The uid is PER SESSION -- "
                         "measured rotating 0xa756a69a -> 0xa455a599 inside one "
                         "process -- so keyed on it a player's roster split and "
                         "their characters vanished between sessions. Also the key "
                         "the lobby reads for the DoC content profile. Empty = the "
                         "old uid keying (the emulator, dev).")
    ap.add_argument("--pol-members", default="off", choices=("on", "off"),
                    help="sec 4ft: on = key the --chara-store PER CLIENT by the POL "
                         "member signed in at that client's address -- the login "
                         "service's `session` table in the core's PostgreSQL "
                         "database, read only. Supersedes --account, which is ONE "
                         "key for every client: with two machines in --peer it "
                         "filed both players' characters into one roster "
                         "(2026-09-13: the Deck's delete removed the PC's). "
                         "Fallbacks: the member last resolved at that address "
                         "(the doc_ip_member table), then an addr:<ip> key -- "
                         "never a shared bucket. Also names a new --units unit "
                         "after its POL group. off = --account, as before.")
    ap.add_argument("--accounts-db", default="",
                    help="the old spelling of --pol-members on: any value turns "
                         "it on. The path is not read (the core's accounts are "
                         "in PostgreSQL).")
    ap.add_argument("--chara-id-source", default="derived", choices=("derived", "content"),
                    help="2026-10-05: content = a NEW character (REGISTER) takes one "
                         "of its POL member's DoC Content IDs (code 10) as its "
                         "character id -- the client keeps a memory-card gun "
                         "loadout only for one. A character that already carries "
                         "one ('cid' in doc_character, set by "
                         "doc_contentid_migrate.py or a REGISTER) is served it "
                         "under either setting.")
    ap.add_argument("--chara-id-base", type=lambda x: int(x, 0), default=0x1000,
                    help="sec 4dv: the base for the CHARACTER ID written at "
                         "wire+0 of each roster record. That u32 becomes "
                         "[kelsvc+272] at lobby phase 25 -- the id getMyCharaId() "
                         "returns, the key the name plate and the battletable "
                         "check look themselves up by, and the value the client "
                         "then stamps into record+4 of every message it sends. "
                         "We shipped 0 for every character ever created, which "
                         "is why the client looked itself up as id 0. 0 here "
                         "restores that old behaviour. Bits 30/31 are masked "
                         "off on purpose (sec 4bw peer-table side, sec 4ch "
                         "sign-extending cache key).")
    ap.add_argument("--bt-start-ready", action="store_true", default=False,
                    help="sec 4ex (2026-09-11): clamp the SERVED battletable "
                         "current-participants field (BT_OFF_CUR) to >= 2 so the "
                         "'Start Immediately' gate (0x00aa0d98: [config+2] >= 2 "
                         "OR FLAGS & 0x00010000) passes for a SOLO leader. Without "
                         "it a solo-created table serves cur=1 and the client "
                         "shows 0x683b 'Conditions for victory are not configured. "
                         "Battle cannot begin.' The gate reads the SERVER-served "
                         "browser-list record, not the player's menu edits, so "
                         "this is the only lever. Pairs with --gs-fake-teammates "
                         "for the actual battle roster. Cosmetic: the browser then "
                         "shows the table as 2/max.")
    ap.add_argument("--world-self-charaid", action="store_true", default=False,
                    help="sec 4ev (2026-09-11): on the world-door answer "
                         "(selector 2), OVERRIDE body[44..47] with the client's "
                         "CHARAID (seen_charid = [kelsvc+272], record+4 of its "
                         "requests) instead of echoing the UID from the session "
                         "token. mgr+304 [rec+52] (the battletable-data manager's "
                         "self record key) is set from body[44]; keying it by the "
                         "UID while getMyReservationTableId() looks up by charaid "
                         "-> a self-lookup MISS -> the getter returns an "
                         "uninitialised buffer value the 0x6835 'already reserved' "
                         "gate reads (sec 4eu). Charaid here makes the lookup HIT "
                         "a clean record -> 0xffff -> Create allowed. WARNING: "
                         "body[44] overlaps the echoed session token (token+16); "
                         "if the client re-validates the token this may disturb "
                         "world entry -- OFF by default, revert by dropping it.")
    ap.add_argument("--self-hp", type=int, default=100,
                    help="2026-09-13: the player's HP, written as a u32 at body[48..51] "
                         "of the world-door answer (selector 2) -- world-door "
                         "record+4, which setUserData 0x00be6580 copies into the "
                         "self record's CURRENT (R+44) and MAX (R+752) HP. We used "
                         "to echo the session token there: HP read -31166/-31166. "
                         "WARNING: 100 is a PLACEHOLDER until real per-character stats "
                         "are served. 0 = echo the token as before. With "
                         "--suit-hp on this is only the fallback for a login "
                         "whose suit is unknown.")
    ap.add_argument("--suit-hp", default="on", choices=("on", "off"),
                    help="2026-09-24: the world-door HP follows the EQUIPPED SUIT "
                         "(body[80]) through the retail durability table "
                         "(doc_gear.suit_hp: Sniper 210, Speed 240, Magic 250, "
                         "Soldier 270, Toughness 340; bgd.bin block +0x3fc). "
                         "off = --self-hp for everyone.")
    ap.add_argument("--shop", default="",
                    help="sec 4gk: on = the per-character wallet + bag store (the "
                         "doc_wallet table; the path of the old doc-shop.json "
                         "also means on and is not read). "
                         "When on, the lobby's shop lists (64 stock, 141 recipes, "
                         "143 prices) are served, a 145 item transaction gets a "
                         "real 146 verdict (check gil, apply, persist), and the "
                         "world-door answer carries the character's gil (body[52]) "
                         "and bag (body[140]/[240+]). Empty = OFF: the old empty "
                         "answers, and the echoed token as gil.")
    ap.add_argument("--shop-stock", default="",
                    help="JSON stock/price override for --shop: {\"start_gil\": N, "
                         "\"stock\": [{\"id\": \"0x69320000\", \"price\": 50}, ...]}. "
                         "Empty = doc_shop.DEFAULT_STOCK (the 2006 retail guides' "
                         "prices, 2026-09-26).")
    ap.add_argument("--shop-start-gil", type=int, default=None,
                    help="gil a character's wallet starts with (default: the "
                         "--shop-stock file's start_gil, else %d)"
                         % doc_shop.START_GIL)
    ap.add_argument("--no-trade", dest="trade", action="store_false", default=True,
                    help="sec 4gk addendum 5: do NOT relay player-to-player trades "
                         "(41 invite / 43 offer / 47 confirm / 49 cancel -> pushes "
                         "42 / 44 / 50 / 48, wallets swapped on both confirms). "
                         "Trading is on whenever --shop is.")
    ap.add_argument("--issue-ammo", default="standard",
                    help="sec 4go (2026-09-13): bullets are INVENTORY ITEMS and "
                         "the magazine fills from them (0x004a5780), so an "
                         "empty bag = a gun that never fires. Tops the "
                         "world-door bag up to these every login, NOT "
                         "persisted, with or without --shop. 'standard' = 36 "
                         "handgun / 18 rifle / 60 MG (the standard "
                         "mission supplies), 'off', or 'ID:QTY,...'.")
    ap.add_argument("--issue-gear", default="standard",
                    choices=["standard", "off"],
                    help="2026-09-13: the Status window's Mask/Armor rows list the "
                         "bag's masks (0x6330xxxx) and suits (0x6331xxxx) and name "
                         "the EQUIPPED pair, which the world door carries at "
                         "body[76] (mask) / body[80] (suit). 'standard' issues DG "
                         "Soldier Mask M or F (by the selected character's "
                         "gender) + DG Soldier Suit into the bag and equips "
                         "them, every login, NOT persisted. 'off' = the old "
                         "blank rows (body[80] echoes the request).")
    ap.add_argument("--gear-store", default="auto",
                    help="2026-09-13: CHANGE MASK / CHANGE ARMOR (lobby commands "
                         "17 equip / 18 unequip, doc_gear.py) persisted per "
                         "character: answered with the new costume code at 241 "
                         "body[6] (the generic zero answer reset the look) and "
                         "served back on the world door, in the doc_gear table. "
                         "'auto' = on with --shop (off without it), 'on', or "
                         "'off'.")
    ap.add_argument("--rankings", default="",
                    help="2026-09-13: on = the rankings store (the doc_rank_char "
                         "and doc_rank_unit tables; the path of the old "
                         "doc-rankings.json also means on). When on, the "
                         "lobby's Ranking menu (137 Individual -> 138, 149 Unit "
                         "-> 150) is answered with real rows: every character "
                         "in the chara store, ranked on the file's values (0 "
                         "when absent). Empty = the old generic echo, which "
                         "put the page size (30) in the row count and drew 30 "
                         "empty rows. See tools/doc_rank.py.")
    ap.add_argument("--solo-quests", default="1-8,16-40",
                    help="2026-09-13: quest ids the Solo Battle (story mode) "
                         "list offers, answering selector 159 -> 160. Id N is "
                         "named by KelStr group 47 index N-1: 1-8 = the rank "
                         "exams, 9-15 = exams whose text says 'Not yet "
                         "implemented' (left out), 16-36 = named missions. "
                         "2026-09-23: the served (retail-rebased) table has 43 "
                         "rows; 39/40 = Beginner's Course I/II (jungle, real "
                         "briefing text, 300/500 gil). 37/38/41 (Train "
                         "Graveyard / Battlefield Ruins, zones 212/231: no floor "
                         "point yet) and 42/43 (briefing 'Not yet implemented.') "
                         "are left out. "
                         "With --mission-ledger the exams among these are "
                         "gated by the instructors. Empty = the old empty list.")
    ap.add_argument("--mission-spawn-near", type=float, default=150.0,
                    help="2026-10-03: a mission placing FEWER enemies than its "
                         "controller has spawn points uses the points nearest "
                         "the player's start, none closer than this (world "
                         "units). Live quest 1: its lone Beast Soldier stood "
                         "~785 units away all mission. 0 = roster order.")
    ap.add_argument("--mission-player-spawn", default="off", choices=("on", "off"),
                    help="2026-10-04: start a mission at the controller's OWN "
                         "type-2 node (doc_mission_spawns 'player', walkable; "
                         "not a start node) when that sits among more enemies than the "
                         "generic per-zone spawn. Fixes the Wastelands missions "
                         "whose enemies cluster far from the zone spawn (live "
                         "10-04: Dual Horn Duel, Sniper -- empty field). Keeps "
                         "the generic spawn for a mission that already shows "
                         "enemies. OFF until a console check (needs the "
                         "regenerated doc_mission_spawns.json with 'player').")
    ap.add_argument("--peer-record-addr", default="relay", choices=("relay", "off"),
                    help="2026-10-05: what another player's peer record carries at "
                         "+16/+28 (IP/port). 'relay' = our relay endpoint as the "
                         "receiving console sees it (the --gs-connect host via "
                         "advertise.host_for, --gs-connect-port): the console "
                         "copies it into that player's unit and streams to it. "
                         "'off' = zeros, the old record: each console accepted ONE "
                         "relayed peer (retail receive gate 0x00be7dd8), so at most "
                         "two players saw each other.")
    ap.add_argument("--peer-relay-dedupe-s", type=float, default=1.0,
                    help="2026-10-05: relay only the FIRST copy of a peer packet "
                         "(same sender, type, sender clock, body) within this many "
                         "seconds. A console sends one copy per peer unit -- all to "
                         "us once --peer-record-addr=relay gives units our address. "
                         "0 = off.")
    ap.add_argument("--mission-shared-npcs", default="off", choices=("on", "off"),
                    help="2026-10-05: ONE enemy set per mission room, simulated "
                         "by one console (the first to arrive; handed on if it "
                         "leaves) and told to every member, instead of each "
                         "member's console placing and controlling its own copy "
                         "of the same ids. Retail's model; OFF until the peer "
                         "relay carries the controller's enemy movement to the "
                         "others (a non-controller only draws an NPC from those "
                         "updates).")
    ap.add_argument("--mission-player-radius", type=float, default=300.0,
                    help="2026-10-04: the radius (world units) --mission-player-"
                         "spawn counts enemies within when it compares the "
                         "generic spawn against the controller's player nodes.")
    ap.add_argument("--mission-spawn-groups", default="on", choices=("on", "off"),
                    help="2026-10-05: a mission's enemy TYPES and points come from "
                         "the arena's own spawn groups (doc_mission_spawns "
                         "'pool_groups', the original server's picker): fixed "
                         "groups first, then the mission's named target, nearest "
                         "the start; MISSION_SETUP keeps only how many are alive "
                         "at once. off = the row's own types.")
    ap.add_argument("--mission-npc-types",
                    default="4,0,5,6,7,8,9,10,11,12",
                    help="2026-09-23: kind-15 TYPE per mission NPC slot (cycled). "
                         "The controller record carries no type; live, types 1, 4 "
                         "and 52 spawned SOLID but INVISIBLE enemies at the "
                         "controller's spawn nodes. A SWEEP: each slot gets its own "
                         "type and the log names id -> type, so a live look pins "
                         "which value draws the mission's model. Empty = the "
                         "arena test types. 'SIT:t,t;SIT:t;default' sets them per "
                         "situation: live, every type drew situation 3000's "
                         "dog, which reads as type = INDEX into the situation's "
                         "loaded model list (bzd table 20: 3001 = e030 dog, w010, "
                         "w003, e102; 3004 = w003, e102) -- e102 = index 3 / 1. "
                         "2026-10-05: a quest in doc_missions.MISSION_SETUP takes its "
                         "types from there; the 09-23 per-situation pins are gone "
                         "(a 'q39:3,3' pin outlived the course's move to another "
                         "arena, where type 3 is a model it never loads).")
    ap.add_argument("--respawn-kind", type=int, default=13,
                    help="2026-09-23: notify kind pushed about a KO'd member when "
                         "the room's respawn delay elapses; kind 25 (dead bits + "
                         "respawn point) goes out with each counted death. 13 = "
                         "retail respawn: HP max and the state word back to 0. "
                         "18/19 revive the HP but leave state 1 (INVINCIBLE, live "
                         "09-23). 0 = never (down until the battle ends).")
    ap.add_argument("--phoenix-hp", type=int, default=0,
                    help="unused since 2026-09-23 (request 43 is the kill-notice "
                         "ack, not a Phoenix Down); kept so old command lines run.")
    ap.add_argument("--item-use-answer", default="item", choices=("item", "off"),
                    help="2026-09-23: answer game-server request 21 (USE ITEM, "
                         "item id at body+8 -- a Potion in battle) with message "
                         "22 {ident = the player, body+8 = the item id}. 'off' = "
                         "unanswered, as before (the client resends and nothing "
                         "happens).")
    ap.add_argument("--mp-model", default="ledger",
                    choices=("ledger", "full", "zero"),
                    help="2026-09-24: game-server request 60 (MAGIC CAST, arg = "
                         "element | level << 16) is answered with message 61 "
                         "{status 0, MP} and the client takes that MP. 'ledger' "
                         "(tools/doc_magic.py): 100 per battle, each cast charged "
                         "its cost once (resends recognised by their schedule), "
                         "Magic Suit x0.6, 0 on a Magic-restricted table. 'full' = "
                         "always 100 (unlimited casting). 'zero' = the old generic "
                         "answer (MP 0 after the first cast).")
    ap.add_argument("--mp-respawn", default="full", choices=("full", "keep"),
                    help="2026-09-24 (--mp-model ledger): on a KO respawn push "
                         "notify kind 44 with MP 100 ('full', OURS -- the client "
                         "never refills MP on a respawn by itself) or leave the "
                         "MP the player died with ('keep').")
    ap.add_argument("--base-occupy", default="on", choices=("on", "off"),
                    help="2026-09-26: TEAM BASE win = destroy + OCCUPY (the "
                         "January Additional Manual). 'on': a base at HP 0 "
                         "opens an occupation phase; a living member of the "
                         "destroying team standing within --base-occupy-radius "
                         "of the base spot (its type-0x83 pose) for "
                         "--base-occupy-s unbroken seconds wins, and gets the "
                         "Assault medal. 'off' = the old rule: HP 0 ends the "
                         "battle at once.")
    ap.add_argument("--base-occupy-radius", type=float,
                    default=arenadata.BASE_OCCUPY_RADIUS,
                    help="OURS (2026-09-26): horizontal distance from the base "
                         "spot (BASE_POSITIONS) that counts as standing on it.")
    ap.add_argument("--base-occupy-s", type=float, default=arenadata.BASE_OCCUPY_S,
                    help="OURS (2026-09-26): seconds the occupation must last "
                         "(the manual's 'a set time'; no source prints it).")
    ap.add_argument("--mp-points", default="off", choices=("on", "off"),
                    help="2026-09-26 (tools/doc_items.py): MP POINTS. 'on': a "
                         "battle that is not a mission gets notify kind 28 with "
                         "rec[2] = 64 and every mask bit set, so the client's "
                         "zone setup creates the situation's MP points (bzd "
                         "type-8 nodes; the zero record made none), and each "
                         "P2P 117 (touching one with MP below max) is credited "
                         "and pushed with kind 44. 'off' (the default since "
                         "2026-09-26) = the old zero kind 28, 117 ignored: the "
                         "January Additional Manual P.031 moved MP recovery "
                         "from Mako Points to the Ether item, MP full at the "
                         "battle start (a January 2006 player "
                         "blog also reports Mako Points gone). Missions still send their NPC-controller "
                         "28 either way.")
    ap.add_argument("--mp-point-amount", type=int,
                    default=doc_items.MP_POINT_AMOUNT,
                    help="OURS (2026-09-26): MP one MP-point credit adds (the "
                         "client leaves the amount to the server; retail's is "
                         "unknown).")
    ap.add_argument("--mp-point-every", type=float,
                    default=doc_items.MP_POINT_EVERY,
                    help="OURS (2026-09-26): seconds between credits from one MP "
                         "point to one player (the client sends a 117 every "
                         "frame it stands in range).")
    ap.add_argument("--item-use-broadcast", default="on", choices=("on", "off"),
                    help="2026-09-26: send message 22 (the item's effect) about a "
                         "use to every member of the room, not only the user -- "
                         "its arm looks the ident up in the teammate records too "
                         "(0x00bdfb20), so others play the effect on that unit. "
                         "'off' = the user only.")
    ap.add_argument("--mission-ledger", default="on", choices=("on", "off"),
                    help="2026-09-23: MISSION MODE per player (tools/doc_missions.py, "
                         "needs --stats). 'on': the instructors (lobby NPCs 7-10) "
                         "answer command 26 from the career -- no battle yet / "
                         "fewer than three / not enough rank points / the exam "
                         "AUTHORIZED, which adds it to the player's mission "
                         "ledger -- and selector 159 -> 160 lists that ledger's "
                         "exams plus --solo-quests minus every exam. 'off' = the "
                         "old static --solo-quests list for everyone and the "
                         "instructors' greeting.")
    ap.add_argument("--no-quest-mission", dest="quest_mission",
                    action="store_false", default=True,
                    help="2026-09-13: do NOT turn a Start that follows a Solo "
                         "quest pick (lobby command 41) into a MISSION battle. "
                         "By default the next BATTLE READY (38) after a pick "
                         "carries flags 0x00010000 and mission id = the quest "
                         "id; without it the quest plays as a team battle.")
    ap.add_argument("--quest-situations", default="",
                    help="with the quest mission: QUEST:SITUATION pairs "
                         "(e.g. 17:3001) for 38's situation id, the arena "
                         "resource set (3000+ = mission sets). Unlisted = keep "
                         "the table record's own situation. Mapping unknown.")
    ap.add_argument("--quest-zones",
                    default="",
                    help="with the quest mission: QUEST:ZONE pairs for notify "
                         "kind 2's arena zone (rec+26) -- the ARENA; 38's map "
                         "index is list display only. Default = the place each "
                         "quest's own description names, matched to zonelist by "
                         "NAME (church 208, Kalm 203, wastelands 204, sewers "
                         "205, jungle 201) -- inferred, not SE data. Unlisted "
                         "quests keep --gs-battle-zone. 2026-10-05: empty by "
                         "default -- doc_missions.MISSION_SETUP / ARCHIVE_ZONES "
                         "give every served quest its arena, and a pair here "
                         "OVERRIDES them.")
    ap.add_argument("--zone-spawns",
                    default=arenamaps.ZONE_SPAWNS_DEFAULT,
                    help="ZONE:x,y,z entries separated by ';' -- kind 2's spawn "
                         "position (record +0/+4/+8) when the arena is that "
                         "zone. Unlisted zones use --gs-battle-pos (a z201 "
                         "point: live 09-13 it put the player in the VOID of "
                         "z208, the church). Defaults: a floor point from each "
                         "zone's COLLISION mesh (m0xx/mapid.rfd, up = -y, "
                         "2 units above the floor) near its gmap.class map "
                         "centre -- no SE script sets a spawn in these online-"
                         "only zones. 205 has two floor levels (400/365).")
    ap.add_argument("--quest-pick-window", type=float, default=300.0,
                    help="seconds a quest pick stays armed for the next Start")
    ap.add_argument("--rankings-hide-zero", action="store_true",
                    help="with --rankings: list only characters with a nonzero "
                         "value in the asked-for category")
    ap.add_argument("--npc-este-accept", type=float,
                    default=doc_npcquests.ESTE_ACCEPT,
                    help="2026-09-24: the chance Este-D keeps a Dandelion and "
                         "gives the Gasmask (chance decides, per the "
                         "fan archive; no odds published and the player "
                         "guides call it rare -> default %(default)s, OURS). 1 = always, 0 = never.")
    ap.add_argument("--npc-hiren-wither", type=float,
                    default=doc_npcquests.HIREN_WITHER_DAY,
                    help="2026-09-26: Hiren's seed WITHERS when more than this "
                         "many --npc-quest-day days pass between two visits "
                         "while it grows (a January 2006 player blog: about "
                         "once per real day; the exact window is OURS). "
                         "0 = never withers.")
    ap.add_argument("--fuzzy-seed", choices=doc_npcquests.SEED_MODES,
                    default="field",
                    help="2026-09-26: where Hiren's Fuzzy Seed comes from. "
                         "field = ONE on Collector's Mind's field at SE's own "
                         "church generator node (z208 item set 7, the seed at "
                         "100 %%), the picker's server bag credited on the "
                         "pick-up (the fan archive: the seeds are found in "
                         "the Collector's Mind mission); clear = the "
                         "old OURS rule, one per clear; off = none.")
    ap.add_argument("--npc-quest-day", type=float, default=86400.0,
                    help="2026-09-24: seconds per DAY of Hiren's seed "
                         "(2026-09-26: bloom day 5 = the players' 120 h; "
                         "sprout day 2 / bud day 4 OURS). Lower it to test "
                         "the chain quickly.")
    ap.add_argument("--battle-drop-s", type=float, default=90.0,
                    help="2026-09-26: a member of a RUNNING battle whose client "
                         "has sent nothing for this many seconds dropped off "
                         "the line: it leaves the room and, per SE's January "
                         "Additional Manual, loses --leave-rp-penalty rank "
                         "points like a return to the lobby. Default = "
                         "--keepalive-idle-s's 90 (the window already used to "
                         "decide a peer left). 0 = off (a silent member stays "
                         "in the room until the session reaper).")
    ap.add_argument("--leave-rp-penalty", type=int,
                    default=doc_stats.LEAVE_RP_PENALTY,
                    help="2026-09-24: rank points taken from a player who "
                         "RETURNS TO LOBBY (command 4) out of a battle still "
                         "running -- the client's own warning 0x5c0d 'Leaving "
                         "a battle partway through will reduce your rank "
                         "points'. 2026-09-26: default 10, SE's PlayOnline "
                         "Additional Manual; 0 = off. Needs "
                         "--stats.")
    ap.add_argument("--weekly-medals", choices=("on", "off"), default="on",
                    help="2026-09-26: award the four WEEKLY medals (60:[35..38] "
                         "Weekly Rank Points / Defeats / Team Wins / Solo Wins "
                         "1st = medal ids 19..22) when the server clock crosses "
                         "a week boundary, and on startup for any ended week "
                         "not yet closed (the server was down over the "
                         "rollover). Each goes to the week's UNIQUE leader "
                         "with a count above zero; a tie awards nobody "
                         "(doc_stats.WEEKLY_MEDALS). The medal shows in the "
                         "winner's next world-door mask. The week's tallies "
                         "are kept either way; off = never closed. Needs "
                         "--stats.")
    ap.add_argument("--week-start", default=doc_stats.WEEK_START,
                    type=_week_start_arg,
                    help="2026-09-26: when a weekly-medal week starts, 'DAY "
                         "HH:MM +HH:MM' (default %(default)r = Monday "
                         "00:00 JST).")
    ap.add_argument("--test-clock-offset", type=float, default=0.0,
                    help=argparse.SUPPRESS)   # TEST ONLY: seconds added to the
                                              # career / weekly clock
    ap.add_argument("--chocobo-coins", choices=("on", "off"), default="on",
                    help="2026-09-26: pay every Chocobo Coin (0x67300001) a "
                         "player picked up in a battle or mission 1000 gil at "
                         "the end (9 at most, FFCheats) and cut them from its "
                         "bag (kind 21) before the result. off = coins stay "
                         "in the bag and pay nothing (the old behaviour).")
    ap.add_argument("--battle-capture", default="",
                    help="2026-09-24: append one JSON line per relayed P2P "
                         "battle datagram and per game-server request (not "
                         "keepalives) to this file -- type, sender, target, "
                         "table, the whole payload. For matching in-battle "
                         "events (heal, capsule, base, flag) to the messages "
                         "that carry them; the Base Attack medal (base "
                         "damage per attacker) still needs one. Empty = off.")
    ap.add_argument("--stats", default="",
                    help="2026-09-13: on = the CAREER store (tools/doc_stats.py; "
                         "the doc_career, doc_week and doc_week_closed tables; the "
                         "path of the old doc-stats.json also means on). When on: "
                         "the world door carries "
                         "the medal mask / rank points / rank (body[56]/[68]/"
                         "[131]), the Status window's 139 is answered with the "
                         "140 career record (W-L, per-mode results, medal "
                         "counts), the battle END's kind-4 carries the outcome "
                         "and the new rank-point / gil TOTALS (the old zero "
                         "record set both to 0 on screen), and every battle is "
                         "tallied into the store, the --rankings values and the "
                         "Viewer profile. Empty = the old behaviour.")
    ap.add_argument("--units", default="",
                    help="2026-09-13: on = the units store (the doc_unit and "
                         "doc_unit_enlist tables; the path of the old "
                         "doc-units.json also means on). When on, Unit "
                         "Management is answered for real: lobby commands 24 "
                         "(unit info), 13 (areas), 25 (my units), 8 (register), "
                         "12 (modify), 9 (delete), 10 (enlist), 11 (leave), and "
                         "the enlisted unit rides the world door (body[60]). "
                         "Registered units also appear in --rankings' Unit "
                         "Ranking. Empty = the sec 4dy zeroed answer ('you have "
                         "no units'). See tools/doc_unit.py.")
    ap.add_argument("--intro", default="on", choices=("on", "off"),
                    help="2026-09-23 (sec 4hc, tools/doc_novice.py): play the "
                         "retail NEW-PLAYER INTRO once per character -- push "
                         "selector 134 sub-kind 10 event 1 after the lobby spawn "
                         "(selector 13); the client exits to zone 240 (ev2100 "
                         "prologue) -> 241 -> 242 -> lobby and confirms with "
                         "command 27 id 1, which is recorded (career field "
                         "intro_seen) so it never plays again. Needs "
                         "--lobby-zone (sec 4hg addendum 4): the return from "
                         "zone 242 loads the zone in [mgr+0xd94], which the "
                         "world-door answer fills at body[42..43].")
    ap.add_argument("--intro-delay", type=float, default=2.0,
                    help="seconds after the selector-13 lobby spawn before the "
                         "intro push goes out (default 2.0)")
    ap.add_argument("--novice", default="on", choices=("on", "off"),
                    help="2026-09-23 (sec 4hc): the NOVICE ('Beginner') mark. A "
                         "character is a novice until --novice-kills career "
                         "kills or command 33 (the Cactuar 'Beginner's Machine'); "
                         "novices get world-door body[129] bit 0x40 and peer "
                         "FLAGS bit 0x40, graduation is pushed to every lobby "
                         "client as selector 134 sub-kind 11 and recorded "
                         "(career field novice_cleared).")
    ap.add_argument("--novice-kills", type=int,
                    default=doc_novice.KILLS_TO_GRADUATE,
                    help="career kills that remove the novice mark (SE: 20)")
    ap.add_argument("--novice-tables", default="enforce",
                    choices=("enforce", "open"),
                    help="Novice battletables (flags bit 0x04000000, which the "
                         "client sets itself when created from the Novice "
                         "menu): 'enforce' refuses a JOIN by a non-novice, as "
                         "SE's text says ('open only to novice players'); "
                         "'open' lets anyone in.")
    ap.add_argument("--leader-tag", default="on", choices=("on", "off"),
                    help="2026-09-24 (EXPERIMENT): in a Team Leader battle (mode "
                         "byte 5) rename each team's leader '%sName' in the other "
                         "members' peer tables (unsolicited selector-37 answer) "
                         "at the start, and restore it at the end. The client has "
                         "no leader display of its own." % "[L]")
    ap.add_argument("--rp-tables", default="enforce", choices=("enforce", "open"),
                    help="2026-09-26: a table's Minimum / Maximum RP (record "
                         "+64 / +60, flags 0x00100000 / 0x00080000): "
                         "'enforce' refuses a JOIN / RESERVE by a character "
                         "whose career rank points are outside them (the limits "
                         "are the table's game rules; refusal result %d, "
                         "OURS); 'open' ignores "
                         "them. Needs --stats." % battleroom.BT_REFUSE_RP)
    ap.add_argument("--unit-tables", default="enforce", choices=("enforce", "open"),
                    help="2026-09-24: UNIT battletables (flags 0x01000000, needs "
                         "--units). 'enforce' = SE's 28:197: a JOIN is refused "
                         "(-6) unless the joiner's unit is one of the first two "
                         "units seated; 'open' lets anyone in. Either way the "
                         "sides are seated by unit and the result pays each unit "
                         "(doc_unit.record_battle).")
    ap.add_argument("--npc", default="on", choices=("on", "off"),
                    help="2026-09-13: answer the lobby NPC quest-event commands "
                         "(26 check -> the NPC's event id at 241 body[6], 27 done "
                         "and 39 clear -> clean acks). 'off' = the generic 241, "
                         "whose zero body[6] reads as event 0 (the lobby intro). "
                         "See tools/doc_npc.py.")
    ap.add_argument("--npc-events", default="",
                    help="overrides for command 26. TRIGGER:EVENT pins the "
                         "walk-up answer ('7:1180'); TRIGGER:B:EVENT pins one "
                         "follow-up, where B is the scene's sub-code ('4:2:305' "
                         "= what Argento says once the player accepts). Default: "
                         "each NPC's greeting id, else its table's first id, and "
                         "doc_npc.FOLLOWUP for a known (trigger, b); unknown "
                         "triggers are answered 0xffff")
    ap.add_argument("--npc-spawn", default="off", choices=("on", "off"),
                    help="2026-09-13 (static, not yet confirmed on a console): push the lobby "
                         "NPCs the way the game server did -- notify kind 15 'Add "
                         "Npc' with the 33 standing zone/z217/bzd.bin actors, "
                         "--npc-spawn-delay seconds after the client's in-world "
                         "stream starts. OFF by default: live-untested.")
    ap.add_argument("--npc-spawn-delay", type=float, default=10.0,
                    help="seconds after the in-world stream starts before the "
                         "NPC push (default 10: well after ev2046.main has picked "
                         "vl_main, which is what 38-at-entry used to derail)")
    ap.add_argument("--npc-spawn-ready", default="38", choices=("38", "none"),
                    help="how the game-server channel is made READY first. The "
                         "client drops every game-server message but type 29 "
                         "while [chan+2148] is 0, and only selector 38 sets it. "
                         "38 also posts facade 0x208 (the briefing-room flags) -- "
                         "read as harmless mid-lobby, NOT yet confirmed on a console. 'none' = "
                         "send kind 15 alone (dropped unless already ready)")
    ap.add_argument("--npc-spawn-type", default="idx",
                    choices=doc_npc_spawn.TYPE_MODES,
                    help="what goes in entry +8 (the NPC type; its model reader is "
                         "unread): idx = bzd record index (default), num = the "
                         "lnpc number, chr = the bzd type/model field")
    ap.add_argument("--npc-spawn-only", default="",
                    help="lnpc numbers to push, e.g. '4,31,32,33' (default: all)")
    ap.add_argument("--npc-spawn-hp", type=int, default=doc_npc_spawn.DEFAULT_HP,
                    help="entry +4, the NPC's HP")
    ap.add_argument("--npc-spawn-via", default="wu", choices=("wu", "kind15"),
                    help="sec 4gs addendum 5: 'wu' (default) = TYPE-125 world "
                         "updates with nibble-4 ids (0x4000_0000|lnpc, wire+4 = "
                         "bzd record index) -- the client registers them itself "
                         "(0x00bd2358) and builds the bzd chara; no game-server "
                         "channel, no selector 38. 'kind15' = the old notify-15 "
                         "push behind --npc-spawn-ready (38 = BRIEFING ROOM live)")
    ap.add_argument("--npc-spawn-name", default="bzd",
                    choices=doc_npc_spawn.NAME_MODES,
                    help="wire+6 of each NPC record, read by the lobby name plate "
                         "(0x00ace9e0) as a bzd TABLE-0 record index whose +154 "
                         "(the lnpc number) picks msgid 0xd3ff + n: bzd = the bzd "
                         "record index (default); msgid/index/none reproduce "
                         "the '!!na!!' plates seen live 09-13")
    ap.add_argument("--npc-spawn-every", type=float, default=5.0,
                    help="under --npc-spawn-via wu, resend the NPC world updates "
                         "this often while the lobby stream is live (s; 0 = once)")
    ap.add_argument("--npc-arena", default="off", choices=("on", "off"),
                    help="2026-09-13 (sec 4gs addendum 4): the kind-15 TEST where "
                         "the game-server channel is already open -- "
                         "--npc-arena-after s after the battle GO (--gs-battle-go), "
                         "push one NPC per --npc-arena-types value in a ring "
                         "around the arena spawn. Asks only: does kind 15 draw, "
                         "and which type draws what. No selector 38.")
    ap.add_argument("--npc-arena-after", type=float, default=5.0,
                    help="seconds after the battle GO before the arena ring")
    ap.add_argument("--npc-arena-types", default=doc_npc_spawn.ARENA_TYPES_DEFAULT,
                    help="entry +8 values, one NPC each, placed in this order "
                         "counter-clockwise from +x (default "
                         + doc_npc_spawn.ARENA_TYPES_DEFAULT + ")")
    ap.add_argument("--npc-arena-radius", type=float, default=150.0,
                    help="ring radius around the arena spawn, world units")
    ap.add_argument("--unit-fee", type=int, default=0,
                    help="with --units: gil charged to register or modify a unit "
                         "(answer body[6]; the client deducts it, and a --shop "
                         "wallet pays it too). SE's figure is not known; 0 = free.")
    ap.add_argument("--no-self-name", dest="self_name", action="store_false",
                    default=True,
                    help="2026-09-13: do NOT write the selected character's name "
                         "into body[112..127] of the world-door answer (character "
                         "record +68 -> self record R+704). Without it the own "
                         "table's owner and the own team entry read blank.")
    ap.add_argument("--chara-chrcode", type=lambda x: int(x, 0), default=None,
                    help="APPEARANCE EXPERIMENT (sec 4dr, 2026-09-10). Stamp this "
                         "64-bit 'chr code' into wire+0x10..0x17 (LE) of every "
                         "USED roster record (needs --chara-store). The o099 "
                         "costume builder 0x006ec748 reads a 64-bit word from "
                         "[actor+0x440]: bit32 = gender (0='m',1='f'), bit33 = "
                         "face-model flag, then a 6-bit cursor walks the six part "
                         "variants ((code>>34)&0xff and (code>>42)&0xff are two of "
                         "them). Whether the LIST record feeds that word is the one "
                         "unproven link -- so serve a KNOWN value, select the "
                         "character, enter, and read the emulog: `chr load request "
                         "[o099][0x%%08x]`, `chr resource loaded o099 [...]`, and "
                         "the `o099_f_NN` resource names. If they change, this field "
                         "IS the appearance and we can dress from --chara-store; if "
                         "not, the costume rides the user-data/JVM path (sec 4dt). "
                         "Suggested first value 0x0000302b00000000: bit32=1 "
                         "(female), bit33=1 (face flag), (>>34)&0xff=0x0a and "
                         "(>>42)&0xff=0x0c (two part variants) -- a male default "
                         "reads 0, so female is the clean single-bit discriminator. "
                         "None = off (record stays name+used).")
    ap.add_argument("--self-costume-probe", action="store_true",
                    help="APPEARANCE OFFSET PROBE (sec 4dr, 2026-09-11). Stamp "
                         "distinct u16 markers across body[96..112] of the "
                         "selector-2 and selector-13 world-answer replies (base "
                         "0xB000 for sel 2, 0xC000 for sel 13; marker at body[N] "
                         "= base|N). The self avatar's costume code X is stored "
                         "at [0x009f3f88] from a field of that reply; boot ONCE, "
                         "enter the lobby with a character, take a savestate and "
                         "read [0x009f3f88] -- e.g. 0xB068 means the selector-2 "
                         "reply, X at body+0x68 (body+104). That pins the exact "
                         "wire offset with no guessing on the entry path (the "
                         "window is past the session token and clear of the "
                         "body[140] SE-crash count). OFF by default; inert "
                         "diagnostic. Then --self-costume packs the real code "
                         "there. See the 2026-09-05 audit.")
    ap.add_argument("--self-costume", type=lambda x: int(x, 0), default=None,
                    help="DRESS THE LOBBY AVATAR (sec 4dr, offset LIVE-pinned "
                         "2026-09-11). Pack this 16-bit costume code into body+100 "
                         "of the selector-2 world-door reply -- the field the "
                         "client stores at [0x009f3f88] and the o099 builder "
                         "0x006ec748 dresses from (repacker 0x005a2598: gender = "
                         "bit6, faceFlag = NOT bit7, varA = faceFlag?(x>>10)&3:"
                         "(x>>6)&0x3c, varB = (x>>3)&7, varC = x&3). e.g. 0x0000 = "
                         "male all-default; 0x0040 = female. None = off (leave the "
                         "field as-is). WARNING: dresses the OWN lobby avatar only; the "
                         "character-select preview is a separate source. The "
                         "app92/app93 charamake nibbles -> this code mapping is "
                         "not yet located, so this is a RAW code for now; "
                         "--chara-store-driven auto-dressing is --self-costume-auto.")
    ap.add_argument("--self-costume-auto", action="store_true",
                    help="AUTO-DRESS the lobby avatar from --chara-store (sec 4dr). "
                         "On the selector-2 world-door reply, read the SELECTED "
                         "character id from the request (body+80, u32 -- MEASURED), "
                         "match it to the account's roster, and pack "
                         "doc_charastore.chr_code(that char) into body+100 so the "
                         "avatar wears the created face/armor/color. Needs "
                         "--chara-store. --self-costume (raw) overrides it. The "
                         "nibble->variant mapping is our own (SE's is lost) but "
                         "deterministic; refine chr_code if an element is on the "
                         "wrong slot. OFF by default.")
    ap.add_argument("--self-costume-file", default=None,
                    help="LIVE COSTUME CALIBRATION (sec 4dr). Path to a file whose "
                         "contents (a hex/int u16, e.g. 0x0402) are read FRESH on "
                         "every selector-2 reply and packed at body+100, overriding "
                         "--self-costume and --self-costume-auto. Lets the costume "
                         "code be changed with a plain file write and one lobby "
                         "re-entry -- no container recreate -- to map the creation "
                         "menu numbers onto the o099 part variants by eye. Empty or "
                         "missing file = fall through to auto/raw. Remove when done.")
    ap.add_argument("--lobby-chara-count", type=int, default=-1,
                    help="THE CHARACTER LIST.  If >=0, every code-8 (selector-8) reply "
                         "carries a character-select payload: body[17] = this count and, "
                         "if non-zero, that many 96-byte records from body[20].  The "
                         "state-6 handler 0x00587c10 copies them into the game buffer at "
                         "[nest+0xF4] (16 slots x 96 B + a 16-byte header -- the arithmetic "
                         "the emulog set chara data buffer 1552 confirms).  -1 = off, which "
                         "keeps the known-good sustain reply (body[17] forced to 0 = zero "
                         "characters, three blank rows).  MAX %d per message: the client "
                         "decodes into a 560-byte stack record and a sixth would overwrite "
                         "its saved return address." % charrecords.CHARA_MAX_RECORDS)
    ap.add_argument("--lobby-chara-allow", type=int, default=-1,
                    help="body[16] -> buf[1], the byte NEXT to the count.  Believed to be "
                         "the slot allowance / create-character permission, but that is "
                         "INFERENCE: the UI that reads it lives in lobby.pex, never "
                         "disassembled.  NB it has never been zero -- the sustain reply "
                         "reuses the client token, whose byte 16 is 0x4c (76) in every "
                         "captured packet, and no create affordance has ever appeared. "
                         "-1 = leave the token byte alone.")
    ap.add_argument("--lobby-chara-name", default=None,
                    help="string written at wire+0x20 (24 B) -> buf+0x40 of each record. "
                         "Default BBBBBBn.")
    ap.add_argument("--lobby-chara-name-a", default=None,
                    help="string written at wire+0x44 (16 B) -> buf+0x00 of each record. "
                         "Default AAAAAAn.  BOTH blocks are wide enough to be the name and "
                         "we do not know which the UI draws -- send both, and whichever "
                         "renders on screen names the field.")
    ap.add_argument("--no-charamake-answer", dest="charamake_answer",
                    action="store_false", default=True,
                    help="do NOT answer the 232-byte REGISTER submission with a "
                         "selector-16. On by default: the submission parks the nest at "
                         "state 10 and phase 10's poll 0x00588cf8 spins while [nest+8] "
                         "== 10, which is the -47111(phase = 10) death. Code 16 is the "
                         "response gated on state 10 (handler 0x00587e98): it sets "
                         "[nest+8] = 2, after which the poll returns [nest+20] or 1 and "
                         "the phase advances.")
    ap.add_argument("--no-delete-answer", dest="delete_answer",
                    action="store_false", default=True,
                    help="do NOT answer the slot-DELETE request. DELETE sends a 40-byte "
                         "mode-2 message with body `05 11 00 00 <slot>` -- selector 17, "
                         "slot index at body[4] -- and the even code gated on the state it "
                         "parks in is 18 (0x00587f00), by the same request/response pairing "
                         "as the charamake's 16.")
    ap.add_argument("--no-world-answer", dest="world_answer",
                    action="store_false", default=True,
                    help="do NOT answer the type-0x7f GAME SERVER request. Selecting a "
                         "server sends a 132-byte mode-1 datagram whose INNER type is "
                         "127 (main is 128, the lobby nest 129) and phase 28 then polls "
                         "kelsvc vt+44 = 0x00bdb250 for [kelsvc+12] == 2. Nothing else "
                         "sets that field in time, so the 40 s receive watchdog "
                         "0x00589a58 stamps it -1 and the run dies -1(phase = 28) / "
                         "CER-48102. See --world-selector.")
    ap.add_argument("--world-len", type=int, default=0,
                    help="OPTIONAL exact-length filter on the game-server request; 0 (the "
                         "default) disables it and routes purely on the inner type, which is "
                         "what the client actually demuxes on. Phase 27's request is 132 "
                         "bytes, but phases 29 and 31 send their own sizes on the same "
                         "channel (sec 4bn), so a length filter answers phase 28 and nothing "
                         "after it. Set 132 to restore the old phase-28-only behaviour.")
    ap.add_argument("--gs-connect", action="store_true",
                    help="CONNECT THE GAME SERVER CHANNEL once the client is in "
                         "world, by sending selector 104 (writes the endpoint at "
                         "[0x009f2b40+184]) then selector 38 (sets the ready flag "
                         "[chan+2148] = 1). sec 4cd: the item/stat manager's count "
                         "getter is 0x0058e210 -> 0x00bc60d8, which reads that very "
                         "channel and bails unless [chan+2148] == 1 -- which is why "
                         "`init item number -1`, a flashing -1 HP bar and a nonsense "
                         "item count. Proven offline: the count goes -1 -> 0 once "
                         "both land. WARNING: sec 4bu called this channel a red herring; "
                         "true for the WORLD DOOR, false for the stat system.")
    ap.add_argument("--gs-stats", default="",
                    help="entries for the game-server STAT TALLY, as a comma "
                         "list of ITEM_ID:QUANTITY (at most 6 -- the handler "
                         "clamps COUNT to 6). Confirmed live: each entry prints "
                         "`You obtain %%s x%%d.` (msgid 0x9c29) in chat, from the "
                         "loop at 0x00ad93f8. WARNING: ids 16/17/18 resolved to "
                         "`??id??`, the item-name-by-id failure, so the valid id "
                         "space is unknown and item names are NOT in KelStr. "
                         "WARNING: AMOUNTS ACCUMULATE: 0x00be6b20 ADDS "
                         "to a key that is already present, so sending the same "
                         "message twice doubles it and a sweep leaves residue "
                         "on the character. WARNING: The KEY NUMBERING is not "
                         "decoded; the 24 medal names are group 60 entries "
                         "16..39, so both a 0-based medal index and the msgid "
                         "low byte are live candidates.")
    ap.add_argument("--gs-arm-state", type=int, default=1,
                    help="the STATE byte (body[13]) of the game-server arming "
                         "message 27. 0x00bc1548: bit 0 -> [array+0] = 1, bit 1 "
                         "-> 2, anything else -> 0. We shipped 0 first and the "
                         "Status screen's Rank Points went 0 -> -1, so 0 is "
                         "very likely 'no data'. 1 is the cheapest probe there "
                         "is -- it needs no knowledge of the key space and "
                         "leaves no accumulating residue, because COUNT stays 0.")
    ap.add_argument("--gs-keepalive-ms", type=int, default=15000,
                    help="hold the GAME SERVER channel open, which is what "
                         "CER-48101 actually is (sec 4cq). The client's own "
                         "emulog says `timeout gameserver 40006` one line before "
                         "the error: 0x00bc10d4 fires when now - [chan+224] "
                         "exceeds [chan+12] == 40000 ms. [chan+224] is a "
                         "LAST-HEARD stamp that only refreshes once the channel "
                         "is ARMED -- message %d with a body of at least %d "
                         "bytes, the only site in the binary that ORs 0x40 into "
                         "[chan+204]. So this sends the arming message once "
                         "after --gs-connect and then message %d every N ms. 0 "
                         "disables. WARNING: the arming message does not itself "
                         "refresh the stamp: 0x00bc4e98 tests the bit before "
                         "dispatching to the handler that sets it, so it takes "
                         "two." % (gamemsg.GS_ARM_MSG, gamemsg.GS_ARM_MIN_BODY, gamemsg.GS_KEEPALIVE_MSG))
    ap.add_argument("--gs-rearm-ms", type=int, default=0,
                    help="sec 4cx. Redo --gs-connect (selector 104 + 38) and "
                         "the arm every N ms, not just once per world session. "
                         "0 (the default) keeps the old behaviour. The client "
                         "RESETS the game-server channel at 0x00bc03b8 -- four "
                         "callers, one of them the plain interface close -- and "
                         "that zeroes [chan+2148], so the item/stat manager goes "
                         "back to `init item number -1` for the rest of the "
                         "session and nothing on the wire says so. Re-running the "
                         "two selectors recovers it (measured in "
                         "an offline run of the client's own code (doc_gsseq_proof)). WARNING: OFF by default "
                         "because the arm is message %d, a reward GRANT: run it "
                         "with --gs-stats EMPTY or every cycle grants again."
                         % gamemsg.GS_ARM_MSG)
    ap.add_argument("--gs-msg", default="",
                    help="after --gs-connect opens the game-server channel, "
                         "send these application messages on it -- a comma list "
                         "of type numbers, 1..61 (sec 4cq). The channel is where "
                         "the item/stat data lives and CER-48101 is the client "
                         "asking to retry a handshake on it. WARNING: PROBE: the body "
                         "format of each message is NOT decoded, so this sends "
                         "the type and zeros. It answers 'does any game-server "
                         "traffic quiet the retry', not 'is the payload right'. "
                         "Proven offline (doc_gsreply_proof.py): all 61 types "
                         "are accepted by the client's own handler and 43 of "
                         "them share a do-nothing epilogue, so a sweep is safe.")
    ap.add_argument("--no-gs-answer", dest="gs_answer", action="store_false",
                    default=True,
                    help="sec 4ea: do NOT answer the client's game-server "
                         "requests (31/33/36/47/56/58/60 -> type+1, keepalive "
                         "1 -> 1). Default on: every request the client makes "
                         "on the type-130 channel is answered by name.")
    ap.add_argument("--gs-battle-start", default=briefingroom.GS_BATTLE_START_DEFAULT,
                    help="sec 4ea/4fy: the notify kinds (message 35) pushed "
                         "after answering 47 (leaveBriefingRoom) with 48, once "
                         "per battle: KIND[:HEXPAYLOAD],... Default 2 alone "
                         "(the spawn + the arena zone); 5 and 53 follow as "
                         "--gs-battle-go (sec 4ga). WARNING: NOT 4: kind 4 is the RESULT -- its arm "
                         "0x00bc1760 sets facade 0x40, which ends ev2045's "
                         "battle loop at once (the live 09-13 instant win / "
                         "defeat); --gs-battle-length sends it at the end.")
    ap.add_argument("--gs-battle-length", type=float, default=180.0,
                    help="sec 4fy: seconds after the battle starts (request 47) "
                         "to END it: notify kind 4 (the RESULT, facade 0x40) "
                         "and then, --gs-battle-reset-after s later, selector "
                         "39 (the full battle reset 0x00bd2a38) so the client "
                         "returns to the LOBBY instead of hanging in br_main. "
                         "0 = never end.")
    ap.add_argument("--gs-battle-reset-after", type=float, default=8.0,
                    help="sec 4fy: seconds between the result (kind 4) and "
                         "selector 39, the time the result screen is shown.")
    ap.add_argument("--gs-battle-after-join", type=float, default=25.0,
                    help="sec 4ed: seconds after the last team join (request 31) "
                         "to push --gs-battle-start, because the briefing room "
                         "offers no 'ready' button -- the real server started "
                         "the table on a timer / head count. 0 = never; 47 "
                         "(leaveBriefingRoom) still triggers it immediately.")
    ap.add_argument("--gs-team-notify", dest="gs_team_notify",
                    action="store_true", default=False,
                    help="sec 4ee: push notify kind 20 (PLAYER DISTRIBUTION) "
                         "after a team join. OFF by default: the arm posts "
                         "facade 0x1000 UNCONDITIONALLY, which the briefing loop "
                         "reads as 'distribution determined' and FINALIZES the "
                         "teams with whoever is seated (1 in a solo test), then "
                         "tries to enter the arena, fails (ID_NO_USE), and exits "
                         "to the title. It is the match-start signal, not a "
                         "per-join update; there is no provisional form.")
    ap.add_argument("--gs-fake-teammates", type=int, default=0,
                    help="sec 4ei: after a team join (request 31), push notify "
                         "kind 31 (add chara) for this many BOT ids into the team "
                         "the client just joined -- NON-finalizing (no kind 20, "
                         "no facade 0x1000), so the team roster fills and the "
                         "count moves WITHOUT the ID_NO_USE kick. The client skips "
                         "its own id, so this is how a solo tester sees a "
                         "populated team; it also probes whether a populated team "
                         "unlocks the 'start' console action (the arena gate, sec "
                         "4eh). 0 = off.")
    ap.add_argument("--gs-fake-team-base", type=lambda x: int(x, 0),
                    default=0x9000,
                    help="base character id for --gs-fake-teammates bots "
                         "(bot k = base + k). Kept clear of real roster ids.")
    ap.add_argument("--gs-battle-zone", type=int, default=201,
                    help="sec 4ft: the ARENA ZONE number served in notify kind "
                         "2's record +26 -> [chan+1064], which vl_main reads "
                         "through get_onlinezone() after the distribution window "
                         "and hands to KerberosZone.exit(). 0 = the old zero "
                         "record, which get_onlinezone turns into exit(-1) = the "
                         "title (the sec 4ee/4el bounce). Default 201 = z201; "
                         "doc-proto-test.img carries z201..z237 with geometry "
                         "(sec 4fb). WARNING: A CONSTANT: which zone SE served for "
                         "which table map is not decoded (the map table "
                         "0x00afc68c holds only KelStr ids).")
    ap.add_argument("--gs-battle-map", default="0,0",
                    help="sec 4ft: map0,map1 for kind 2's record +24/+25 "
                         "(get_onlinezone's mapnum0/mapnum1 -> exit_l). 0,0 "
                         "unless proven otherwise. WARNING: sec 4hb: this is NOT the "
                         "battletable's map index -- z201 and z208 were both "
                         "entered live with 0,0, so the ZONE byte picks the "
                         "arena and these do not. Use --battle-map-zones.")
    ap.add_argument("--zone-pieces", default=arenamaps.ZONE_PIECES_DEFAULT,
                    help="2026-09-23: ZONE:M0,M1 entries separated by ';' -- "
                         "kind 2's rec+24/+25 (exit_l's map0/map1) for that "
                         "arena zone, overriding --gs-battle-map. Names the "
                         "zone's TERRAIN piece so it loads on arrival: with "
                         "0,0 z204 loaded only its sky (m000) and never its "
                         "ground (m001). off = --gs-battle-map everywhere. "
                         "Default %s." % arenamaps.ZONE_PIECES_DEFAULT)
    ap.add_argument("--battle-map-zones", default="",
                    help="sec 4hb: IDX:ZONE pairs mapping the battletable "
                         "record's MAP BYTE (BT_OFF_MAP -- what the config "
                         "screen's Map picker writes) to the arena zone kind 2 "
                         "serves at rec+26. Empty = the decoded default "
                         "(BT_MAP_ZONES_DEFAULT): the 20 of 28 roster entries "
                         "whose label matches a 'multi' (maruchi) arena in the title's "
                         "own data/zone/zonelist.txt. 'off' = none, i.e. every "
                         "table plays in --gs-battle-zone (the behaviour up to "
                         "2026-09-23, which is the bug: the map was chosen and "
                         "then discarded). WARNING: NOT linear -- 201+idx is right "
                         "only for 0..7.")
    ap.add_argument("--no-battle-map-zone", dest="battle_map_zone",
                    action="store_false", default=True,
                    help="sec 4hb: do NOT let a table's chosen map choose the "
                         "arena zone; serve --gs-battle-zone for every table. "
                         "A mission battle keeps --quest-zones either way.")
    # KEY: DEFAULT FLIPPED 2026-09-23 (design decision): serve the chosen map's zone even
    # with no floor point for it. The guard was the safer default while nothing
    # could pick a map, but it is self-defeating now -- a spawn point for z209
    # can only be surveyed from inside z209, and the guard is exactly what keeps
    # us out. Landing in the void is a recoverable, informative failure; never
    # entering the zone is not. Pass --battle-map-needs-spawn to restore it.
    ap.add_argument("--battle-map-needs-spawn", dest="battle_map_needs_spawn",
                    action="store_true", default=False,
                    help="sec 4hb: keep a table in --gs-battle-zone when no "
                         "--zone-spawns point exists for its map's arena zone. "
                         "OFF by default since 2026-09-23: we follow the map "
                         "regardless, because "
                         "kind 2's fallback spawn is a z201 point and sec 4gr "
                         "already landed a player in the VOID that way ('I am "
                         "in the church map! -- but in the VOID'). Pass it to "
                         "keep every player on a floor, at the cost of the "
                         "chosen map being ignored for 15 of the 20 arenas.")
    ap.add_argument("--gs-no-real-roster", dest="gs_real_roster",
                    action="store_false", default=True,
                    help="sec 4ft: do NOT feed the REAL table members into the "
                         "briefing. Default on, and a no-op unless the player's "
                         "battletable has 2+ seated members: each request 31 "
                         "then pushes notify kind 31 (add chara) for every other "
                         "member to every member (kind 0 on a team change), and "
                         "--gs-fake-teammates is skipped at that table.")
    ap.add_argument("--gs-no-real-distribution", dest="gs_real_dist",
                    action="store_false", default=True,
                    help="sec 4ft: do NOT push the kind-20 distribution over a "
                         "real 2+-member roster. Default on: once every seated "
                         "member is on a team and both sides are occupied for "
                         "--gs-real-dist-settle s, every member gets kind 20 -> "
                         "the 'Player distribution has been determined' window "
                         "-> leaveBriefingRoom (47) -> get_onlinezone -> the "
                         "arena (--gs-battle-zone).")
    ap.add_argument("--gs-add-chara-before-dist", default="on", choices=("on", "off"),
                    help="2026-10-03: right before the distribution (kind 20), "
                         "send each client a notify 31 (add chara, with team and "
                         "the distribution's slot) for every OTHER member, so "
                         "its profile cache holds their teams -- without it a "
                         "TEAM battle's non-leaders took everyone for a teammate "
                         "and never sent a hit (live 10-03). off = the old kind "
                         "0 / kind 20 only.")
    ap.add_argument("--gs-real-dist-settle", type=float, default=5.0,
                    help="sec 4ft: seconds the real roster must stay ready "
                         "before the distribution goes out, so a player can "
                         "still change sides. Checked on each request 31, which "
                         "the briefing room re-sends every 1-4 s.")
    ap.add_argument("--no-gs-rearm-until-team", dest="gs_rearm_until_team",
                    action="store_false", default=True,
                    help="2026-09-23: do NOT re-send the message-27 arm on each "
                         "keepalive after a 38 until the client's first team "
                         "request (31/33). Default on: a client whose one 27 "
                         "was lost can keep alive but never send request 31.")
    ap.add_argument("--gs-auto-team-after", type=float, default=120.0,
                    help="2026-09-23: seconds after a 2+-member Start before a "
                         "seated member who never chose a team (no request 31) "
                         "is put on the smaller side, so the distribution still "
                         "goes out. The table record's Briefing Time (wire+111, "
                         "minutes) wins when set. Negative = never.")
    ap.add_argument("--gs-no-briefing-clock", dest="gs_briefing_clock",
                    action="store_false", default=True,
                    help="2026-09-24: do NOT hold the battle start for the "
                         "table's Briefing Time (wire+111 minutes). By default "
                         "a table with one and two or more seated players "
                         "starts when the countdown the players see reaches "
                         "0 (a solo table never waits for it); this restores the old start "
                         "(ready + --gs-real-dist-settle, solo "
                         "--gs-battle-after-join after the first team step).")
    ap.add_argument("--gs-no-rebalance", dest="gs_rebalance",
                    action="store_false", default=True,
                    help="2026-09-24: do NOT move players when the briefing "
                         "time is up and everyone stands on ONE side (by "
                         "default the last half in seat order is moved to the "
                         "other side so the battle can start).")
    ap.add_argument("--gs-briefing-minute", type=float, default=60.0,
                    help="seconds per Briefing Time minute (60; the e2e tests "
                         "shorten it)")
    ap.add_argument("--gs-no-solo-distribution", dest="gs_solo_dist",
                    action="store_false", default=True,
                    help="sec 4fv: do NOT push the kind-20 distribution "
                         "to a SOLO leader. Default on: when the post-join "
                         "timer pushes --gs-battle-start (kind 2 carrying "
                         "--gs-battle-zone), a table with fewer than 2 seated "
                         "members also gets kind 20 over its own roster -> the "
                         "'Player distribution has been determined' window -> "
                         "OK -> leaveBriefingRoom (47) -> get_onlinezone -> "
                         "KerberosZone.exit(zone). A no-op at 2+ members, "
                         "where --gs-no-real-distribution's push owns it.")
    ap.add_argument("--bt-kill-target", type=int, default=0,
                    help="sec 4he: FALLBACK kill target (team points that end "
                         "the battle) for a table whose record carries none "
                         "decoded yet (BT_RULE_FIELDS). 0 = time limit only. "
                         "The record's own Conditions for Victory row wins "
                         "once its wire byte is measured.")
    ap.add_argument("--bt-respawn-s", type=float, default=4.0,
                    help="sec 4he: FALLBACK respawn delay when the record's "
                         "wire+111 is 0 (the client's own HUD delay is "
                         "record[+57]*1000 + 4000 ms). Negative = never.")
    ap.add_argument("--bt-time-unit", type=float, default=1.0,
                    help="sec 4he: seconds per count of the record's Time Limit "
                         "(wire+4 u32; the picker commit 0x00aac21c writes "
                         "minutes*60, so 1 = the record is already seconds). "
                         "0 = ignore the record, use --gs-battle-length.")
    ap.add_argument("--no-p2p-relay", dest="p2p_relay", action="store_false",
                    default=True,
                    help="sec 4he: do NOT relay the P2P battle layer (shots "
                         "112, damage 113, entity messages) between the "
                         "members of a table. Default relays; without it "
                         "nobody can be hit.")
    ap.add_argument("--bt-situation", type=int, default=1100,
                    help="sec 4gc: the battle SITUATION ID stamped into every "
                         "served battletable record whose wire +34 is 0 -> "
                         "[0x00bf4530]+100 -> getBattleSituationId -> ev2045 "
                         "mdlResLoad: 1000-1098 Res_bt1 (battle), 1100-1998 "
                         "Res_tbt1 (team battle, the default: the briefing has "
                         "two teams), 2000-2098 Res_fa1, 2100-2998 Res_tfa1, "
                         "3000+ missions. 0 = the old zero (no battle set "
                         "loads).")
    ap.add_argument("--bt-no-start-all", dest="bt_start_all",
                    action="store_false", default=True,
                    help="sec 4ft: when the LEADER's Start (lobby command 3) "
                         "pushes BATTLE READY, do NOT also push it to the other "
                         "seated members. Default on: only the leader sends "
                         "command 3, so without this a joiner never reaches the "
                         "briefing room (38 alone takes a reserved member there, "
                         "sec 4eo).")
    ap.add_argument("--post-battle-briefing", type=float, default=0.0,
                    help="2026-10-01, manual p.33: seconds the players stay in the "
                         "briefing room after the result, leaving by its "
                         "transporter (lobby command 4); selector 39 sends anyone "
                         "left to the lobby when it runs out. 0 (default) = the "
                         "old direct return, selector 39 after "
                         "--gs-battle-reset-after. Not yet seen on a console: "
                         "the 09-13 attempt hung in the briefing load.")
    ap.add_argument("--lobby-capacity", type=int, default=0,
                    help="2026-10-01, manual p.25: players a lobby takes; at or "
                         "past it Select Server shows the row as full (Players "
                         "Connected 1000+, which the client will not enter). 0 = "
                         "no limit (SE's number is not known).")
    ap.add_argument("--no-respawn-random", dest="respawn_random",
                    action="store_false", default=True,
                    help="2026-10-01: respawn a KO'd player at its OWN first "
                         "spawn point every time, instead of a random one of "
                         "its team's (manual p.33; BT: anyone's).")
    ap.add_argument("--no-status-echo", dest="status_echo",
                    action="store_false", default=True,
                    help="2026-10-01: do NOT echo a player's battle status "
                         "(request 46) to the room as notify kind 43. Without the "
                         "echo Limit Break never starts and Reraise never shows.")
    ap.add_argument("--no-team-full-refuse", dest="team_full_refuse",
                    action="store_false", default=True,
                    help="2026-10-01: do NOT refuse a briefing-room team pick "
                         "when that side already holds half the table's player "
                         "limit (manual p.30; answer 32 = CER-44301).")
    ap.add_argument("--briefing-start", default="ready", choices=("ready", "full"),
                    help="2026-10-01: when a briefing room sends everyone to "
                         "the battlefield before its countdown ends. ready = "
                         "manual p.30: as soon as every seated player is ready "
                         "(on a team, both sides occupied; missions: any side). "
                         "full = the 09-29 rule: a PvP table only when it is "
                         "full to its player limit, else at the countdown.")
    ap.add_argument("--bt-fill-start", type=float, default=2.0,
                    help="2026-10-01, manual p.29: a PvP table whose last seat "
                         "is taken goes to the briefing room by itself (\"when "
                         "the table fills, or the leader starts it\"). Seconds "
                         "after the filling JOIN, so its own answer and echo go "
                         "out first; a seat freed in that time cancels it. "
                         "Negative = only the leader's Start.")
    ap.add_argument("--rematch-after", type=float, default=15.0,
                    help="2026-10-03, manual p.33 (\"after the battle you jump "
                         "back to the briefing room\"): a finished PvP table is "
                         "KEPT, and this many seconds after the battle-over "
                         "reset (selector 39, which lands the client in the "
                         "lobby) everyone still in it, plus anyone queued "
                         "(--join-queue), gets BATTLE READY again, as a filled "
                         "table does. Missions still dissolve. Negative = "
                         "dissolve every table after its battle (the old way).")
    ap.add_argument("--join-queue", default="on", choices=("on", "off"),
                    help="2026-10-03: a JOIN refused because the table's briefing "
                         "or battle is running (-4) is remembered, and the player "
                         "is seated and sent to the briefing room with the next "
                         "round (--rematch-after). Seats still count: queue + "
                         "members never exceed the table's maximum.")
    ap.add_argument("--join-queue-ttl", type=float, default=900.0,
                    help="seconds a queued join stays valid")
    ap.add_argument("--gs-battle-pos", default="925.4,-12.3,-1271.7",
                    help="sec 4ga: x,y,z of the battle spawn (notify kind 2 "
                         "record +0/+4/+8 -> getBattleInitPos -> "
                         "btl_start_set's setpos). Default = the one z201 "
                         "point in the client's own ev2045 (battlefield's "
                         "respawn path, beside Zone.load(201,...)) -- a "
                         "CANDIDATE, not SE's per-team spawn. 0,0,0 = the old "
                         "void corner.")
    ap.add_argument("--gs-battle-rot", type=float, default=0.0,
                    help="sec 4ga: spawn facing in degrees -> kind 2 record "
                         "+12/+20 = (sin, cos), read by get_battle_rot_l.")
    ap.add_argument("--gs-battle-go", default=briefingroom.GS_BATTLE_GO_DEFAULT,
                    help="sec 4ga: the notify kinds sent --gs-battle-go-after "
                         "s after the battle starts (request 47): 5 = START "
                         "(facade 0x80, releases ev2045's waitlogin), 28/29/3/"
                         "30 = the zero-record arena handshake that opens the "
                         "DAMAGE gate (facade 0x20, sec 4he). (53 was dropped "
                         "2026-09-24: the retail client ignores kinds >= 49.) "
                         "Empty = never.")
    ap.add_argument("--gs-battle-go-after", type=float, default=20.0,
                    help="sec 4ga: seconds between request 47 and --gs-battle-"
                         "go. Kind 5 before ev2045 reads the spawn makes the "
                         "client spawn at its own last position (the void "
                         "corner); later only delays the start.")
    ap.add_argument("--no-field-items", dest="field_items",
                    action="store_false", default=True,
                    help="2026-09-26: do NOT run the arena's item generators "
                         "(doc_field: ammo / Potions / Ethers / ... placed with "
                         "kind 10 from the map's own generator points).")
    ap.add_argument("--field-respawn-s", type=float,
                    default=doc_field.RESPAWN_S,
                    help="seconds before an emptied item generator rolls again "
                         "(OURS: the map data carries no interval)")
    ap.add_argument("--enemy-drops", default="on", choices=("on", "off"),
                    help="2026-09-24 / ported 10-05: a mission enemy's death "
                         "rolls the retail client's own drop table (doc_drops: "
                         "9 handgun / 4 rifle / 30 MG bullets, Potions, Phoenix "
                         "Downs) and lays the drop on the field (kind 10) where "
                         "it died. The client's own roll is off online.")
    ap.add_argument("--drop-seed", type=int, default=-1,
                    help="seed the enemy-drop roll (tests); -1 = unseeded")
    ap.add_argument("--no-respawn-ammo", dest="respawn_ammo",
                    action="store_false", default=True,
                    help="2026-09-26: send kind 25 (down) WITHOUT the respawn "
                         "refill list (the battle's BULLETS, each SET to "
                         "max(supplies ledger, battle-start count) in the "
                         "victim's bag; retail's 03-24 rule, "
                         "doc_missions.respawn_refill) -- the old empty "
                         "20-byte payload.")
    ap.add_argument("--no-mission-supplies", dest="mission_supplies",
                    action="store_false", default=True,
                    help="2026-09-26: do NOT top each player up to the battle's "
                         "supplies (doc_missions.SUPPLIES; the standard issue "
                         "for PvP) with message 27 at its request 47.")
    ap.add_argument("--battle-go-wait", type=float, default=20.0,
                    help="2026-09-26: a battle room sends ONE GO to every member, "
                         "--gs-battle-go-after s after the LATEST request 47, and "
                         "starts its clock at that GO (each client's HUD clock "
                         "starts at its kind 5). This caps how much a late 47 can "
                         "push the shared GO back past the first 47's; a member "
                         "later than that gets its own GO and a shorter battle.")
    ap.add_argument("--no-gs-ready-roster", dest="gs_ready_roster",
                    action="store_false", default=True,
                    help="sec 4ea: send selector 38 WITHOUT the session id / "
                         "roster (the old all-zero body).")
    ap.add_argument("--gs-ready-after", default="",
                    help="sec 4dx: send SELECTOR 38 -- the battle-READY flag -- "
                         "immediately after answering these answer-selectors. "
                         "Comma list; empty (the default) never sends it. "
                         "38's arm 0x00bccf04 -> 0x00bcb838 -> 0x00bc0260 is the "
                         "SOLE writer of [chan+2148] = 1, which is what makes "
                         "the client send its game-server hello and what opens "
                         "leaveBriefingRoom()'s door (sec 4di). "
                         "the 2026-09-05 audit missing #2 asked for exactly this knob: "
                         "38 is not a connect step, it is 'your battle instance "
                         "is ready', and sending it at WORLD ENTRY is what "
                         "produced the briefing-room slingshot -- a match "
                         "declared ready before anyone reserved one. "
                         "`21` is the honest trigger: selector 21 is the "
                         "phase-44 answer, i.e. the last rung of a COMPLETED "
                         "reservation (sec 4dw). "
                         "WARNING: if this re-opens the slingshot the answer is NOT "
                         "to drop 38 again -- that re-breaks the door -- it is "
                         "that the trigger is still too early.")
    ap.add_argument("--gs-connect-selectors", default="104",
                    help="which game-server connect selectors --gs-connect sends "
                         "(sec 4df). 104 writes the ENDPOINT, which the item/stat "
                         "manager needs; 38 sets the READY flag, which is what "
                         "sends the client to the briefing room on every world "
                         "entry. The default keeps both, i.e. the behaviour that "
                         "shipped; `104` alone tests whether the endpoint gives a "
                         "working avatar without claiming a match is ready.")
    ap.add_argument("--gs-connect-ip", default=None,
                    help="endpoint for --gs-connect (default: --lobby-ip).")
    ap.add_argument("--no-gs-start-endpoint", dest="gs_start_endpoint",
                    action="store_false", default=True,
                    help="sec 4gv: do NOT re-declare the game-server endpoint "
                         "(selector %d) immediately before the BATTLE READY "
                         "(selector %d) + message-%d re-arm pair at Start. "
                         "Default ON. The client's game-server receive handler "
                         "DROPS every datagram whose source does not equal the "
                         "endpoint selector %d last wrote into [chan+184..191], "
                         "before dispatch and before the sequence window -- and "
                         "that endpoint is written once per world session, at "
                         "--gs-connect. Any channel reset between the connect "
                         "and the Start (0x00bc03b8, sec 4cx) leaves it stale, "
                         "the re-arm is swallowed at the gate, [chan+204] bit 6 "
                         "is never set, [chan+224] is never refreshed and the "
                         "client paints CER-48101 40 s later. MEASURED live: "
                         "the peer whose connect->Start gap "
                         "was 2 m 10 s sent ZERO game-server hellos and its "
                         "[chan+212] was still 65528. Unlike --gs-rearm-ms this "
                         "sends selector %d ONLY (never message %d on its own), "
                         "so it grants nothing."
                         % (worldchannel.GS_ENDPOINT_SELECTOR, worldchannel.GS_READY_SELECTOR, gamemsg.GS_ARM_MSG,
                            worldchannel.GS_ENDPOINT_SELECTOR, worldchannel.GS_ENDPOINT_SELECTOR,
                            gamemsg.GS_ARM_MSG))
    ap.add_argument("--gs-connect-port", type=int, default=55040,
                    help="port for --gs-connect.")
    ap.add_argument("--gs-connect-id", type=int, default=0,
                    help="u16 written to body[58..59] of the selector-104 message, "
                         "which 0x00bca938 stores at [kelsvc+268] (sh r3, 268(r17) "
                         "at 0x00bca9c0). sec 4cf: that field is the id the client "
                         "resolves names through, and when it cannot the UI renders "
                         "`!!na!!` -- the whole Status page 2 is that one lookup "
                         "failing, not thirteen missing strings. It reads 65535 "
                         "before --gs-connect and 0 after (this default), and both "
                         "are evidently 'none'. sec 4bs also calls it the argument "
                         "of the follow-up kind-18 request -- and selector 18 DID "
                         "appear on the wire once the channel opened, so the loop "
                         "is: set an id here, the client asks about it on 18, we "
                         "answer 19 with a user list carrying that id and a name.")
    ap.add_argument("--kelsvc-keepalive-ms", type=int, default=15000,
                    help="send a type-127 no-op every N ms to refresh the "
                         "client's KELSVC receive watchdog. 0 disables. sec 4cc: "
                         "CER-48102 is that watchdog -- [conn+4] = 40000 ms "
                         "against [conn+32], i.e. [kelsvc+8] and [kelsvc+36]. The "
                         "existing --lobby-keepalive-ms feeds the type-129 nest, "
                         "NOT kelsvc, and we otherwise send type-127 only when the "
                         "client asks. So a player who is busy in menus or walking "
                         "around -- transmitting constantly, but not REQUESTING -- "
                         "gets 40 s of kelsvc silence from us and the watchdog "
                         "fires. Measured: the receive driver 0x005895b0 stamps "
                         "[conn+32] = now_ms() in its tail (0x005896ec) for EVERY "
                         "message it handles, whatever the selector.")
    ap.add_argument("--kelsvc-keepalive-selector", type=int, default=20,
                    help="selector for --kelsvc-keepalive-ms. MUST be one of the "
                         "194 that map to the shared no-op arm 0x00bcd788, so the "
                         "refresh costs nothing: verified offline that state "
                         "[kelsvc+12] and flags [kelsvc+28] are both unchanged "
                         "while [kelsvc+36] refreshes. WARNING: Do NOT point this at a "
                         "real arm -- see sec 4bz, where a state-setting fallback "
                         "silently reset the connection.")
    ap.add_argument("--pending-ack-after", default="13",
                    help="comma list of ANSWER selectors after which to also send "
                         "a bare selector-128 acknowledgement. Default 13. "
                         "sec 4ca: selector 13 releases phase 30 (it sets state 2 "
                         "and [kelsvc+1064]) but its arm 0x00bcca00 NEVER CLEARS "
                         "THE PENDING MARKER, bit 31 of [kelsvc+28] -- so the "
                         "client's own 10 s deadline in 0x00589af0 expires and it "
                         "paints CER-47117, every time, while resending the "
                         "request with exponential backoff. Selector 128's arm "
                         "0x00bcd4a4 is a bare ack: clear bit 31, set state 2, "
                         "nothing else. Empty string disables.")
    ap.add_argument("--pending-ack-selector", type=int, default=128,
                    help="the bare-acknowledgement selector for "
                         "--pending-ack-after (128 and 136 share arm 0x00bcd4a4).")
    ap.add_argument("--short-ladder", default="22",
                    help="comma-separated SELECTORS whose request is a 36-byte "
                         "datagram (12-byte body) and which we should still "
                         "answer. sec 4dv: selector 22 is the reserve's server "
                         "handoff -- phase 42 sends it, phase 43 blocks on the "
                         "selector-23 answer, and the old 40-byte length gate "
                         "dropped all seven of them in the 09-05 corpus, which "
                         "is the CER-47117 reservation stall. Keep 5 OUT of "
                         "this list: it is a driver arm and answering it moves "
                         "[kelsvc+12] (sec 4bz). Empty string disables.")
    ap.add_argument("--chat", choices=("on", "all", "off"), default="on",
                    help="2026-09-26: relay chat (world selector 255, kinds "
                         "0..9) with ident = the speaker, SCOPED as retail "
                         "(doc_chat): say = same lobby area, shout = + the "
                         "adjacent areas, entry = same battletable, team = "
                         "same team, tell = its target. ALL = every non-tell "
                         "line to every live player (the first relay); OFF = "
                         "the old drop.")
    ap.add_argument("--world-answer-unpairable", action="store_true",
                    help="ALSO answer request selectors that cannot be paired "
                         "(0, or >= 255) using --world-selector-next. OFF by "
                         "default since sec 4bz: that default is 2, and selector "
                         "2 is a DRIVER arm that sets [kelsvc+12] = 2, so "
                         "'answering' a selector-255 notification silently reset "
                         "the connection state out from under whatever request "
                         "was pending. 255 cannot pair anyway -- 256 is past the "
                         "end of the 252-entry jump table.")
    ap.add_argument("--world-selector-next", type=int, default=2,
                    help="answer SELECTOR for the rounds after the world door (phase 29 on). "
                         "WARNING: Briefly defaulted to 5 on the reasoning that the state [conn+8] sits "
                         "at 2 after the world door and 5 is the only arm live there. That was "
                         "WRONG: the state was read from a savestate taken during phase 27's "
                         "processing. Every client SEND resets it -- 0x00589924/0x0058992c does "
                         "`[conn+8] = 1` -- so phase 29's request leaves the state at 1 again and "
                         "selector 2 is right for every round. 2 is also the ONLY selector that "
                         "reaches 0x005894f0, which clears the pending-request marker at "
                         "[conn+24] (= kelsvc+28) that 0x00589af0 times out on after 10 s. Kept "
                         "as a flag so the four selectors the driver accepts (2/4/5/6) can be "
                         "swept without a rebuild.")
    ap.add_argument("--no-world-selector-pair", dest="world_selector_pair",
                    action="store_false", default=True,
                    help="do NOT derive the answer selector as `request selector + 1` "
                         "(sec 4bs); fall back to --world-selector / "
                         "--world-selector-next. The pairing is what finally answered "
                         "phase 30: the driver 0x005895b0 RETURNS body[1] and the demux "
                         "0x00bcc718 dispatches it through the jump table at 0x00bf3230 "
                         "(index = selector - 4), so phase 29's `07 0c ..` (selector 12) "
                         "wants selector 13 -- handler 0x00bca868, which is the only "
                         "code that sets BOTH [kelsvc+12] = 2 and [kelsvc+1064], the two "
                         "things phase 30's poll 0x00bd0888 requires. Selectors 2/4/5/6 "
                         "are the DRIVER's arms and none of them can do it. Turn this "
                         "off only to reproduce the pre-4bs behaviour.")
    ap.add_argument("--lobby-clock", default="play",
                    help="command 20's answer body[16] = the Status screen's PLAY "
                         "TIME in seconds (2026-09-13; sec 4dc called it the server "
                         "clock). 'play' (default) serves the selected character's "
                         "tracked play time (doc_playtime.py); 'unix' the old epoch "
                         "seconds (renders ~496,000 h); an INTEGER forces a value; "
                         "'off' echoes the request's stale bytes. The client asks "
                         "only while its slot is empty.")
    ap.add_argument("--play-time", default=None,
                    help="per-character play time for --lobby-clock play, in the "
                         "doc_playtime table. Default: on with --chara-store "
                         "(memory only without it); 'on'; 'off' = memory only.")
    ap.add_argument("--lobby-cmd", default="echo",
                    help="selector 241 (Command Result) body[12]: 'echo' takes "
                         "the command id out of the client's own selector-240 "
                         "request (the default -- 0x00589c48 writes it at "
                         "request body[12] as a single byte), an INTEGER forces "
                         "one sub-type, 'off' restores the pre-fix behaviour of "
                         "sending --world-result there. WARNING: 'off' means the answer "
                         "bails at 0x00bc9274 every time, which is what shipped "
                         "until 2026-08-28.")
    ap.add_argument("--world-result", type=int, default=0,
                    help="body[12..15] of the world answer = `record+32`, the RESULT the "
                         "selector-13 handler reads first. It is copied verbatim into "
                         "[kelsvc+1064], and phase 30 fails if it is negative. 0 = ok. "
                         "Set a negative value to make the client report a server-side "
                         "refusal instead of hanging.")
    ap.add_argument("--world-gs-ip", default="",
                    help="GAME SERVER address to hand the client in body[52..55] of a "
                         "selector-21 answer (sec 4bs). 0x00bca938 passes it to "
                         "0x0058a970, which fills the sockaddr at [0x009f2b40 + 184] -- "
                         "the channel that has been 0.0.0.0:0 in every savestate, and "
                         "the reason its demux 0x00bc4e98 logs `[KEL NET GAME "
                         "SERVER]Drop packet bad packet` for anything that arrives. "
                         "Empty leaves body[52..] as the request left it (zeros).")
    ap.add_argument("--world-gs-port", type=int, default=55040,
                    help="GAME SERVER port, body[56..57] of a selector-21 answer, "
                         "written big-endian. Calibrated: with the IP in network-order "
                         "octets and the port big-endian the client stores exactly the "
                         "same 8 bytes it already holds for the live lobby endpoint.")
    ap.add_argument("--world-pad", type=int, default=176,
                    help="pad the world-door reply's BODY to this many bytes with zeros. "
                         "THIS IS THE SE-CRASH FIX (sec 4bo): the client reads a 32-bit array "
                         "count from body[140], and echoing the 132-byte request only supplies "
                         "body[0..107], so it read stale RAM (measured: 0, 1040, 2149, -1529, "
                         "15360) and a copy loop wrote count*8 bytes over the SE record-array "
                         "base. 176 covers body[140..143] with margin; 0 disables padding and "
                         "restores the old, crashing behaviour.")
    ap.add_argument("--lobby-map-mask", default="all",
                    help="WHICH MAPS THE BATTLETABLE MAP PICKER OFFERS (sec 4gv). A "
                         "64-bit bitmask over the client's own 28-entry map roster, "
                         "carried at body[72..79] of the SAME selector-13 answer the "
                         "spawn rides. The picker skips every roster entry whose bit is "
                         "clear, so the zero we shipped until now is exactly why that "
                         "list has rendered EMPTY since 2026-09-12 -- and why only the "
                         "Map row was affected: every other row on that screen builds "
                         "its options against an all-0xFF mask the client makes up "
                         "locally. 'all' (default) = every map except index 11, which "
                         "is a hole in SE's own string table and would show as "
                         "'!!na!!'. 'none' restores the old, empty behaviour. Also "
                         "accepts a mask (0x0ffff7ff) or a comma list of roster indices "
                         "(0,4,7). WARNING: The index space is the battletable record's map "
                         "byte (BT_OFF_MAP), so whatever you allow here is what a "
                         "created table can ask the game server to host.")
    ap.add_argument("--lobby-zone", type=int, default=217,
                    help="2026-09-23 (sec 4hg addendum 4): the zone number the "
                         "world-door answer (selector 2) carries at body[42..43] "
                         "-> [mgr+0xd94], the zone z217's lobby-entry fallback "
                         "loads when nothing is resident (every return from an "
                         "event zone). 217 = the lobby entry. 0 = the old "
                         "behaviour (the echoed token bytes = a junk zone = the "
                         "intro's black screen).")
    ap.add_argument("--lobby-spawn", default="",
                    help="WHERE THE PLAYER APPEARS IN THE LOBBY (sec 4dh). Empty = off, "
                         "which ships body[28..53] as zeros and is the p(0,0,0) spawn "
                         "outside the level that sec 4df measured. Accepts "
                         "'x,y,z[,dirx,diry,dirz[,index]]' or a preset: 'east' (the "
                         "Visual Lobby's east wing, where quest.ev stands the player), "
                         "'east-anchor'/'south'/'west'/'north' (the four map-screen "
                         "anchors of mm_z217, one per wing), or 'room' -- which is a "
                         "BRIEFING ROOM seat (ev2046_sub.vl_brf2), the spot sec 4dd "
                         "measured with selector 38 armed; in the Visual Lobby it is "
                         "the middle of nowhere (the 2026-09-05 audit). Rides "
                         "selector 13 -- the phase-30 "
                         "answer -- whose arm 0x00bca868 stores a 28-byte descriptor at "
                         "[0x009f3b80+3232]; the zone script reads it back through "
                         "KerberosNetLobby.getLobbyInitPos(). Y is given as the WORLD "
                         "position: the getter subtracts 3.0 and we add it back here.")
    ap.add_argument("--world-type", type=int, default=127,
                    help="inner type of the world-door reply. 127 routes the datagram to "
                         "kelsvc (0x009f3480), whose [kelsvc+16] == 7 bounds body[0] and "
                         "whose [kelsvc+12] is the field phase 28 polls.")
    ap.add_argument("--list-148", default="",
                    help="sec 4gt add.1 PROBE (2026-09-22), default OFF: answer the "
                         "selector-147 list request with a REAL selector-148 "
                         "list instead of the generic zero-length one. Either a "
                         "bare COUNT (\"8\" -> ids 1..8, record index i, "
                         "flags 0) or `id:rec:flags` triples "
                         "(`1:0:1,2:1:3`). body[15] = count, then 4 bytes per "
                         "entry {u16 id, u8 record index, u8 flags}; the "
                         "client's populator 0x00aae2d0 turns flags bit0 into "
                         "rec+26 (229 vs -1) and bit1 into rec+4 (0 vs 2), and "
                         "the builder 0x00aae890 draws idx[i] out of the "
                         "52-byte table at 0x00B89548. WARNING: A PROBE: the meaning "
                         "of the ids is UNKNOWN and it is NOT established that "
                         "this list feeds the battletable config rows. It "
                         "answers one question -- does a non-zero count put "
                         "rows on screen. Empty = the old behaviour.")
    ap.add_argument("--battletable-list", default="",
                    help="serve a real BATTLETABLE LIST on selector 16 -> 17 "
                         "(sec 4dv). Either a COUNT (\"3\") or "
                         "\"map:cur/max:comment;...\", e.g. "
                         "\"jungle:0/8:Come on in;church:2/16:Large-Scale\". "
                         "Maps: " + ", ".join(tablerecords.BT_MAPS) + ". The browser asks at "
                         "lobby phase 34 and parks the channel in state 15; the "
                         "accumulator 0x00bc9a70 keys each row on the record's "
                         "u16 at +24 and renders map / participants / comment / "
                         "leader name. Empty = the old empty-body answer.")
    ap.add_argument("--battletable-probe", action="store_true",
                    help="answer the selector-26 battletable request with a "
                         "selector-27 record whose every field is a distinct "
                         "sentinel (sec 4dn/4do). The config screen (Map / Max "
                         "Players / Time Limit / Point / Comment / Restrictions "
                         "/ NPC) currently renders !!na!! because we answer with "
                         "zeros; this names which record offset drives which "
                         "row. SHIPS MADE-UP VALUES -- a probe, not a table.")
    ap.add_argument("--no-battletable-verbs", dest="battletable_verbs",
                    action="store_false", default=True,
                    help="sec 4dz: do NOT serve the battletable console verbs "
                         "out of the store (create 24, config 26, adjust 28, "
                         "reserve 151/153, cancel 155, dissolve 125, invite "
                         "127, and the join 20/30 seating). With this set they "
                         "fall back to the generic zero-body answer.")
    ap.add_argument("--bt-no-onfly-reserve", action="store_true",
                    default=False,
                    help="sec 4eo/4ep (2026-09-11): do NOT create-on-the-fly "
                         "and seat the player for a JOIN whose table id is "
                         "UNKNOWN (the online battletable console "
                         "default-targets the uninitialised [manager+11808] "
                         "= 59600). Left on (the default), the sec-4ee "
                         "create-on-the-fly seats the player and the "
                         "generic selector-21 endpoint answer then sets the "
                         "client reserved flag [kelsvc+1092] bit 4, so the "
                         "player is PERPETUALLY reserved (prompt 0x6835) "
                         "and the Create option is hidden -- they can never "
                         "become a table leader. With this set the phantom "
                         "JOIN is NOT invented and is answered selector 21 "
                         "with result=-1 (no such table), so the phase-45 "
                         "success path never runs and the reserved flag "
                         "stays clear -- the player is free to CREATE. A "
                         "real listed table (--battletable-list) or a real "
                         "CREATE (selector 24) is unaffected.")
    ap.add_argument("--bt-no-start-ready", action="store_true",
                    default=False,
                    help="sec 4fm (2026-09-12): do NOT push BATTLE READY "
                         "(selector 38, roster per --no-gs-ready-roster) right "
                         "after answering a selector-240 request whose command "
                         "is 3 = START (0x00bd1db8, what Start Immediately's "
                         "zone flag 10 -> start_onlinebattle sends). Live "
                         "09-12: the leader's Start reached 0x00AA2218, the "
                         "client sent command 3, we echoed 241 and nothing "
                         "followed -- 38 was never sent because --gs-ready-"
                         "after is unset. Default ON; this is the off switch.")
    ap.add_argument("--bt-no-reserve-echo", action="store_true",
                    default=False,
                    help="sec 4fl (2026-09-12): do NOT send the unsolicited "
                         "selector-152 RESERVATION ECHO after a CREATE-ok (25) "
                         "or a successful JOIN-ok (21). The echo is what lets "
                         "the client's Start Immediately pass the 0x683b "
                         "status (it reads the self record R+2970 gated by "
                         "R+684 bit 4, set ONLY by the 152/154 arm); the "
                         "create flow never sends 151 for the leader's own "
                         "table. Default ON; this flag is the off switch.")
    ap.add_argument("--user-list-selector", type=int, default=0,
                    help="force the user-list ANSWER selector instead of "
                         "deriving it as request+1. 0 keeps the pairing. Set "
                         "19 to route every user list onto the rung that "
                         "actually reaches the profile cache: sec 4ch, "
                         "selectors 11 and 19 share the handler 0x00bc9bf0, "
                         "the [kelsvc+12] == 7 gate and the `user list N N` "
                         "log line, and differ only in the argument that picks "
                         "0x00bd8690 -> [kelsvc+280]. The demux dispatches on "
                         "the selector WE send, so this is legal; sec 4ci "
                         "measured 13 requests on 10 and one on 18, i.e. "
                         "almost all of it was landing on the wrong rung.")
    ap.add_argument("--user-list-sweep", type=int, default=0,
                    help="also serve ids 1..N in every user-list answer, on "
                         "top of the one asked for. The record is keyed on its "
                         "+0 and we do not yet know which id the Status window "
                         "resolves; a spread costs only bytes, because the "
                         "client keeps what it wants and the cache holds 32. "
                         "WARNING: a record whose +0 == [kelsvc+272] is dropped "
                         "silently, so id 0 can never be served this way.")
    ap.add_argument("--user-rank", type=int, default=None,
                    help="user record +54, the RANK, 1-BASED: 1 DGD-3, 2 "
                         "DGD-2, 3 DGD-1, 4 DGSC-3 ... 15 DGG-1, 16 TSV. It "
                         "indexes 0x00afd000, whose entry 0 duplicates entry 1, "
                         "and anything >= 17 also falls back to entry 0 -- so 0 "
                         "and 99 both render DGD-3 and NO value means 'no rank' "
                         "(sec 4ch). The label formatter 0x00ad7048 prints it "
                         "as the third field of its `%%s %%s %%s%%s`.")
    ap.add_argument("--user-zone", type=int, default=None,
                    help="user record +32, the SERVER/ZONE id -> profile +64. "
                         "0x00ad6f20 is `return [rec+64] != 0xffff`, so it "
                         "picks msgid 0x7806 'LBY' when the id is 0xffff and "
                         "0x7807 'RES' otherwise, and 0x00ad6188 forces 0xffff "
                         "when the id equals the one being labelled.")
    ap.add_argument("--user-flags", type=int, default=None,
                    help="user record +30 -> profile +62. Bit 1 adds the "
                         "'$m03' marker to the label and bit 4 adds '$m04' "
                         "(0x00ad7104/0x00ad711c). 0x00bd36d0 sets bit 3 "
                         "itself on the group path.")
    ap.add_argument("--user-costume", type=lambda x: int(x, 0), default=None,
                    help="user record +36 (u16), the REMOTE costume code -> "
                         "profile cache, which is where getUserData(id) reads "
                         "the o099 code for a peer whose id != [kelsvc+272] "
                         "(sec 4dr, converter 0x00bd8690). WITH --world-self-"
                         "charaid OFF the self avatar's uid is the ACCOUNT uid "
                         "(!= the charid in [kelsvc+272]), so the client dresses "
                         "ITSELF through this remote path -- serving the code "
                         "here dresses the lobby avatar WITHOUT the flag, so the "
                         "name plate (which needs uid != [kelsvc+272]) keeps "
                         "working. Same 16-bit code as --self-costume; repack() "
                         "expands it on the client (0x1012 = Lex).")
    ap.add_argument("--user-port", type=int, default=None,
                    help="user record +28, the peer's port -> profile +60, "
                         "byte-swapped the same way.")
    ap.add_argument("--user-rec-probe", action="store_true",
                    help="WARNING: A PROBE, NOT A FIX. Fill every still-unknown "
                         "field of the user record with a value that is "
                         "unmistakable on screen -- rank 16 (TSV), zone 3, "
                         "flags 0x12 (both markers), +4=111111, +8=222222, "
                         "+12=333333, +36=4444, +55=55 -- so ONE boot and one "
                         "screenshot say which Status row each field drives. "
                         "It ships deliberately wrong data; do not leave it on.")
    ap.add_argument("--user-list-name", default=None,
                    help="name to put at the user record's +38..53 "
                         "(16 bytes). Defaults to --lobby-chara-name. The "
                         "name plate only checks that byte 0 is alphanumeric "
                         "(0x006b0ed4), so this is what stops the per-frame "
                         "`Name plate error uid` spam -- if +38 is really the "
                         "name, which is what the live run tests.")
    ap.add_argument("--user-list", action="store_true",
                    help="answer the client's selector-10 USER LIST request with "
                         "a real one-entry selector-11 list (sec 4bx) instead of "
                         "build_world_answer's empty body. The single entry is "
                         "the client's OWN uid, learned off its in-game type-0x83 "
                         "broadcast (body[0..3]) -- it is failing to find ITSELF "
                         "(`Name plate error uid 0x%(uid)s` once per frame). OFF "
                         "by default: whether a non-empty list clears CER-47117 "
                         "is exactly what this is for testing."
                         .replace("%(uid)s", "a756a69a"))
    ap.add_argument("--world-update-ms", type=int, default=0,
                    help="send a type-125 WORLD UPDATE this often (ms) while the "
                         "client's type-0x83 position stream is live. 0 = off, the "
                         "default. Nothing has ever sent a type-125, so the world "
                         "has always contained exactly one entity -- the player. "
                         "WARNING: The two record scales (x0.1 position, x0.001 "
                         "orientation) are READ FROM DISASSEMBLY, never measured: "
                         "doc_eemu has no FPU. The live check is whether the peer "
                         "appears where this says it should.")
    ap.add_argument("--world-update-id", type=lambda v: int(v, 0), default=0x40000001,
                    help="entity id for the test peer. Bit 30 picks the table and "
                         "the 0x00bd2358 arm wants the TOP NIBBLE == 4, so the "
                         "default is 0x40000001. The client will not know it and "
                         "will ask selector 36 -- that is the designed pull.")
    ap.add_argument("--world-update-abs", default="",
                    help="absolute x,y,z for the type-125 record instead of an "
                         "offset from the player. With --world-update-id=0 (the "
                         "client's OWN uid) this asks whether a world update can "
                         "PLACE the player -- who otherwise spawns at the origin, "
                         "~1900 units from the level, with no floor and so no "
                         "ability to move (sec 4df).")
    ap.add_argument("--world-update-offset", type=float, default=3.0,
                    help="metres to offset the test peer from the player on X, so "
                         "it is next to them rather than inside them.")
    ap.add_argument("--peer-relay", choices=("off", "raw", "wu"), default="off",
                    help="sec 4fu: TWO CLIENTS SEE EACH OTHER. On every type-0x83 "
                         "position broadcast, put the sender in each OTHER "
                         "in-world client's world: a selector-37 peer record, a "
                         "type-125 spawn at its pose, and then 'raw' = the 0x83 "
                         "itself re-flagged as a peer datagram (flags|8, mode 0, "
                         "verbatim otherwise) for the unit's own update path, or "
                         "'wu' = one type-125 per 0x83 instead. OFF by default "
                         "until proven on two screens.")
    ap.add_argument("--peer-relay-spawn-ms", type=int, default=3000,
                    help="under --peer-relay raw, how often the type-125 (re)spawn "
                         "of each peer is repeated to each other client, so a unit "
                         "the receiver evicted or lost to a zone load comes back.")
    ap.add_argument("--peer-relay-push-s", type=float, default=30.0,
                    help="how often each peer's selector-37 record is re-pushed to "
                         "each other client (its peer table survives, but a "
                         "reconnect empties it).")
    ap.add_argument("--peer-relay-live-s", type=float, default=5.0,
                    help="a client counts as IN WORLD while its own 0x83 stream is "
                         "this fresh; only those are relayed to (the world channel "
                         "is shut everywhere else).")
    ap.add_argument("--peer-push", action="store_true",
                    help="sec 4dj. Send an UNSOLICITED selector-37 peer answer for every "
                         "id the user list carries, so [kelsvc+284] -- the PEER table -- "
                         "actually fills. This is a different table from the profile "
                         "cache [kelsvc+280] the user list feeds, and it is the one "
                         "getCharacterTableId reads (`lw a0, 284(a0)` on kelsvc). "
                         "MEASURED: with --user-list-sweep=32 the cache reached 32 rows "
                         "and the peer table stayed at 0, so every character lookup still "
                         "missed and still returned 0xffff4867 as the table id -- which is "
                         "the 'you already have a reservation' message. Safe to send "
                         "unsolicited: selector 37's arm 0x00bccee8 has no state gate.")
    ap.add_argument("--peer-answer", action="store_true",
                    help="answer the client's selector-36 CACHE MISS with a "
                         "selector-37 peer record (sec 4bw). The client emits "
                         "that request by itself whenever a type-125 world "
                         "update names an entity it does not know. OFF by "
                         "default: nothing sends type-125 yet, and the record we "
                         "would serve is all zeros past the id.")
    ap.add_argument("--world-selector", type=int, default=2,
                    help="body[1] of the world-door reply, the SELECTOR the shared driver "
                         "0x005895b0 dispatches on. 2 at state 1 (post sets state 1) is "
                         "the arm 0x00589660, which calls the sub-object's vt entry 6 = "
                         "0x00bc8aa0, whose FIRST act is 0x005894f0 -- and that sets "
                         "[kelsvc+12] = 2 iff body[4] bit 0 is clear. 5 and 6 also reach "
                         "the state = 2 assignment, but only from state 3.")
    ap.add_argument("--world-subchannel", type=int, default=-1,
                    help="body[0] of the world-door reply; <0 keeps the client's own (7). "
                         "The driver rejects body[0] > [kelsvc+16] == 7 -- a LOOSER bound "
                         "than the nest's 5, which is why the world request may be echoed "
                         "even though a 232/132-byte nest body may not.")
    ap.add_argument("--world-burst", type=int, default=4,
                    help="copies of the world-door answer. A selector outside its gating "
                         "state is a no-op, so repeats are free.")
    ap.add_argument("--charamake-len", type=int, default=232,
                    help="datagram length that identifies the REGISTER submission "
                         "(MEASURED: 232 bytes, mode 2).")
    ap.add_argument("--charamake-burst", type=int, default=4,
                    help="copies of the selector-16 answer. Like the code-8, a selector "
                         "outside its gating state is a no-op, so repeats are free.")
    ap.add_argument("--lobby-chara-used", action="store_true",
                    help="serve records the client renders as REAL characters: the name at "
                         "record+0 and the USED flag, bit 0 of record+58. Both MEASURED off "
                         "the consumer's own branch 0x00ad591c, which reads lbu 106(service "
                         "+ index*96), masks bit 0, and prints either '(not use)' or "
                         "'#%%d %%s' with the string at service+index*96+48 -- i.e. record+0 "
                         "once the +48 copy base is subtracted. Use --lobby-chara-name to "
                         "set the name.")
    ap.add_argument("--lobby-chara-probe", action="store_true",
                    help="THE USED-MARKER SEARCH. Serve four DIFFERENT all-zero records, "
                         "each with one candidate field set, and see which slot stops "
                         "printing '(not use)'. The slots are independent, so this tests "
                         "four hypotheses in one boot: id+0x00, flag+0x04, name+0x44, "
                         "name+0x20. Everything about the record layout is a hypothesis -- "
                         "arbitrary bytes reading as unused (sec 4bb) is the only measured "
                         "fact, so the marker is positive and lives in these 96 bytes.")
    ap.add_argument("--lobby-chara-blank", action="store_true",
                    help="make the --lobby-chara-count records ALL ZERO -- present but "
                         "empty slots -- instead of the populated AAAAAA/BBBBBB test "
                         "records. An empty roster is NOT count=0: char=0 gave four dead "
                         "Unregistered rows and a frozen cursor, while an accidental "
                         "char=145 walked 145 records of arbitrary RAM, reported every one "
                         "as '(not use)', and offered CREATE CHARACTER with a working "
                         "cursor. The client needs records to walk; blank ones are what "
                         "makes a slot selectable.")
    ap.add_argument("--lobby-chara-fill", type=int, default=1,
                    help="value stuffed into the record unknown small fields (default 1). "
                         "Use 0 to test whether a zeroed level/class renders as a blank row.")
    ap.add_argument("--reliable-ack-lo", type=int, default=-1,
                    help="if >=0, ALSO answer every reliable packet (36-B mode-2 / 96-B) with a "
                         "sweep of MODE-0 reliable ACKs for ack-seq in [lo,hi]. The framework "
                         "cancels the retransmit of the pending message whose seq matches (PROVEN "
                         "offline, sec 4ae). The client's seq is encrypted so we sweep; the measured "
                         "first-unacked seq was 28. -1 disables.")
    ap.add_argument("--reliable-ack-hi", type=int, default=90,
                    help="upper bound of the reliable-ACK sweep (see --reliable-ack-lo).")
    ap.add_argument("--reliable-ack-selectors", default="1,3,10,12,18,36,240",
                    help="type-127 request selectors to ACK IMMEDIATELY, whatever "
                         "--reliable-ack-ingame thinks (sec 4dd). Default 240, the "
                         "selectors we ANSWER -- the lobby command channel (240), "
                         "the user list (10/18), the ladder (1/12/3) and the peer "
                         "pull (36). Each arrives while the 2 Hz "
                         "stream is quiet, so the gated ACK lands ~7.7 s late, after "
                         "the client has already timed out and boomeranged back. "
                         "Empty string disables. NOT a return to "
                         "--reliable-ack-exact: this only covers messages we answer, "
                         "where the client is mid-transaction and keeps transmitting.")
    ap.add_argument("--reliable-ack-ingame", action="store_true",
                    help="ACK the client's reliable DATA, but ONLY while its "
                         "in-game type-0x83 position stream is live (within "
                         "--reliable-ack-idle seconds). This is the literal form "
                         "of the rule --reliable-ack-exact violated: never ACK "
                         "the last outstanding retransmit UNLESS SOMETHING ELSE "
                         "KEEPS THE GUEST TRANSMITTING. In the lobby nothing "
                         "does, so ACKing there silences the client and PCSX2 "
                         "unbinds its UDP port ~48 s later (CER-48104, sec 4bx). "
                         "In game the 2 Hz stream holds the mapping open by "
                         "itself, so ACKing is free -- and NOT acking there "
                         "leaves the client resending forever, which is what "
                         "produced the CER-48102 40 s watchdog on 08-27.")
    ap.add_argument("--reliable-ack-idle", type=float, default=5.0,
                    help="seconds since the last type-0x83 within which the "
                         "client counts as 'streaming' for --reliable-ack-ingame.")
    ap.add_argument("--reliable-ack-exact", action="store_true",
                    help="answer each reliable DATA packet with exactly ONE mode-0 ACK for the "
                         "seq read out of its DECRYPTED inner header (sec 4ai), sent AFTER the "
                         "advance replies. Supersedes --reliable-ack-lo/-hi: the sweep was only "
                         "ever a workaround for not being able to read the seq, and it flooded "
                         "the client's receive ring (151 ACKs -> 5 s, 5 ACKs -> 38 s; sec 4ae). "
                         "OFF by default -- the known-good config is a 75 s sustain with no ACK "
                         "at all, and this has NOT been proven live.")
    ap.add_argument("--keepalive-idle-s", type=float, default=90.0,
                    help="stop EVERY unsolicited send (lobby, kelsvc and game-server "
                         "keepalives) once nothing has arrived from the peer for this "
                         "many seconds; 0 = never stop. the 2026-09-05 audit (C): "
                         "the container had sent 7,080 selector-8 keepalives to a peer "
                         "that left two days earlier. Any packet from the peer re-arms.")
    ap.add_argument("--no-session-adopt", dest="session_adopt",
                    action="store_false", default=True,
                    help="sec 4gz: do NOT re-join a client that reappears on a new "
                         "source port to the session it was playing on. Sessions key "
                         "on (ip, port) so two consoles behind one household NAT stay "
                         "apart; adoption is the other half -- a router that re-binds "
                         "the mapping mid-session would otherwise hand the same player "
                         "a blank second session. Off = one session per PORT, full stop.")
    ap.add_argument("--session-adopt-idle", type=float, default=5.0,
                    help="sec 4gz: adopt a predecessor session only once it has been "
                         "silent this long. One client uses ONE socket (measured), so "
                         "two ports sending concurrently under one charid are two "
                         "players whose accounts resolved to the same character -- "
                         "merging those would be the collision, not the fix.")
    ap.add_argument("--session-idle-drop", type=float, default=900.0,
                    help="sec 4gz: forget a session after this many seconds of silence "
                         "(0 = never). With (ip, port) keys the registry grows with "
                         "every re-bound NAT mapping, and a stale entry lingers in the "
                         "connected count and the adoption scan.")
    ap.add_argument("--save-max", type=int, default=20000,
                    help="keep at most this many files in --save, deleting the oldest "
                         "(0 = unbounded). 39,743 had accumulated by 2026-09-05.")
    ap.add_argument("--lobby-keepalive-ms", type=int, default=0,
                    help="if >0, ALSO send the selector-8 advance reply UNSOLICITED every N ms to "
                         "the last peer, using the last 96-byte lobby packet as the template. "
                         "WHY (sec 4aj): the watchdog 0x00589af0 times out on "
                         "(now_ms - nest[+0x24]) > 10000 while armed, and nest[+0x24] is re-stamped "
                         "ONLY by the client's 2->6 self-advance, which only happens after our "
                         "selector-8 answers a state-6 window. Until now the ONLY thing generating "
                         "the inbound packets that made us reply was the client's own unACKed "
                         "retransmits -- so ACKing them silenced the client and the 10 s clock ran "
                         "out (LIVE: 5.1 s, twice). A responder that drives the advance loop on its "
                         "OWN clock does not depend on retransmits. PROVEN OFFLINE "
                         "(an offline run of the client's own code (doc_keepalive_proof)) that an unsolicited selector-8 is a "
                         "harmless no-op at state 2 and advances 6->2 at state 6. 0 disables. "
                         "\n"
                         "MEASURED WINDOW (sec 4al): 9001 < N < 40000. The client's own state-2 poll "
                         "fires only once 9001 ms have passed with NO accepted message from us "
                         "(gate 0x00589a58: elapsed = now - nest[+0x20]), and EVERY accepted message "
                         "re-stamps +0x20 -- so N=1000 makes the poll impossible and the client sits "
                         "mute (LIVE boot 8: 3 packets in 10 minutes). Above nest[+4]=40000 the gate "
                         "returns -1, the error arm. Prefer ~30000: a backstop that lets the client "
                         "poll at ~9 s and drive a real request/response cadence.")
    ap.add_argument("--lobby-keepalive-open-ms", type=int, default=1000,
                    help="keepalive interval during the OPENING window (see --lobby-keepalive-open-s). "
                         "The nest is ARMED with an already-stale nest[+0x24] at LOGIN -- MEASURED "
                         "(an offline run of the client's own code (doc_silence_proof)): from state 6 armed, the tick returns -2 at "
                         "+10.25 s, and the observed death is ~5 s because the liveness is ~5 s old "
                         "before LOGIN even happens. We cannot see when the nest reaches state 6, so "
                         "the opening has to keep trying. Once a selector-8 lands it goes 6->2 and "
                         "DISARMS, and from there the budget is 40 s, not 10.")
    ap.add_argument("--lobby-keepalive-open-s", type=float, default=15.0,
                    help="how long to hold the opening interval before dropping to the steady "
                         "--lobby-keepalive-ms. 0 disables the opening phase entirely.")
    ap.add_argument("--no-decrypt", action="store_true",
                    help="do not decrypt inbound inner headers for the log (decrypt costs ~12 ms "
                         "per packet and is otherwise read-only).")
    ap.add_argument("--lobby-selector", type=int, default=2,
                    help="body[1] of the 'advance' reply = the driver's selector at "
                         "[record+21]. 2 advances the nest at state 1 (default); other values "
                         "are for probing.")
    ap.add_argument("--lobby-seq", type=int, default=0,
                    help="inner-header seq (packet+14) of the 'advance' reply -> record+16. "
                         "Not gated by the advance; tunable in case the reliable layer cares.")
    ap.add_argument("--lobby-edit", default=None,
                    help="patch the echoed LOBBY reply before sending: comma-separated "
                         "OFF:HH byte writes (decimal offset, hex byte), e.g. '25:02' sets "
                         "body[1] (packet+25, the subtype the driver dispatches on) to 2. "
                         "The 16-byte field is NOT validated on receive (proven: echo is not "
                         "dropped), so editing the body is safe. Use to test the selector "
                         "hypothesis: nest object parks at state 1 and needs a selector-2 msg.")
    return ap
