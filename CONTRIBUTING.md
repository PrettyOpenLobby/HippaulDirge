# Contributing to CrystalDirge

CrystalDirge is the Dirge of Cerberus world responder for the OpenLobby core:
one UDP service on port 55040, plus a small title plugin that runs inside the
core. This page says where things are, how to run the checks, and what a pull
request needs.

## Where things are

```
tools/
  docudp.py          entry point (`python docudp.py <flags>`) and a facade
                     over the docworld package; see below
  docworld/          the responder, one module per concern (docworld/__init__.py lists them)
  doc_*.py           the game's rules and stores, one per feature (below)
  doctitle.py        the title plugin: the Viewer's profile, run inside the core
  doc_run_all.py     runs every self-test
  doc_*_e2e.py       end-to-end scripts that drive a real responder on loopback
  facade_rebind_check.py  proves the facade forwards reads and writes
  split/             the tool and map that generated docworld/ from the single file
tests/               newer end-to-end suites
Dockerfile           the responder's image (copies tools/ to /app)
Dockerfile.title     the core image plus doctitle.py
```

The Dockerfile copies `tools/` whole and runs `python docudp.py`, so the
package lives beside the file it came from.

### docworld/

```
framing.py       the datagram: header offsets, the client's checksum, packet
                 decoding for the log, the generic reply and the reliable ACK
handshake.py     the entrance: the subtype-3 server list and the type-129 lobby advance
charrecords.py   the character roster: character ids, the 96-byte record, CHARAMAKE
worlddoor.py     the world-door answer (selector 1 -> 2)
worldchannel.py  the type-127 selector channel: selector names, request bodies,
                 sealing an answer, the sender's ids
lobbycmd.py      lobby commands (selector 240/241) and the clock
arenamaps.py     the lobby spawn and map-picker mask (selector 13), the lobby zone,
                 and the arena zone, pieces and spawn of each map
peerrecords.py   the 56-byte user record other players are cached as (19 and 37)
userlist.py      the lobby user list (10/11 and 18/19)
worldpose.py     positions: the client's uid and pose, the type-125 world update,
                 the relayed position broadcast
tablerecords.py  the 120-byte battletable record and the browser list
tableverbs.py    the battletable store and the console's table verbs
questlist.py     the Solo quest list (160) and the mission list (148)
advertise.py     the address each client is handed (POL_ADVERTISE_PUBLIC / _LAN)
gamemsg.py       the game-server channel (inner type 130): requests, answers, notify kinds
battleroom.py    one battle: its rules (BattleRules) and the running room (BattleRoom)
teamdist.py      the player distribution (notify kind 20) and automatic teams
briefingroom.py  selector 38's ready roster and the burst that starts a battle
arenadata.py     arena data from your own files: mission spawns, NPC controllers,
                 team bases and starts, base occupation
p2pbattle.py     the battle layer between consoles, as far as the server reads it
fielditems.py    items on the field: capsules, drops, pick-ups
cli.py           the command line; its docstring is the `--help` text
worldserver.py   main(): the stores, the socket, the sessions and the event loop
deps.py          the imports the modules share
```

`worldserver.py` is still the largest file. `main()` builds the stores from
the flags, then defines the helpers that share its state (the sessions, the
running battles, the socket) as nested functions, then runs the loop that
answers every datagram. To find where a request is handled, search it for the
selector, request or command number.

The `doc_*.py` modules hold the rules and the per-player stores, and each one
has its own self-test: `doc_charastore` (characters per member),
`doc_stats` (careers, medals, exams), `doc_rank` (rankings), `doc_unit`
(units), `doc_shop` (stock, wallet, bag), `doc_gear` (mask and armour),
`doc_missions` (the mission ledger), `doc_magic` and `doc_items` (MP, item
use), `doc_field` (arena item generators), `doc_npc`, `doc_npc_spawn` and
`doc_npcquests` (lobby NPCs and their quests), `doc_novice` (the intro and
the Beginner mark), `doc_playtime`, `doc_reward`, `doc_trade`, `doc_chat`,
and `doc_kelcrypt` (the world-channel cipher).

Reading order for a first visit:

1. `docworld/worldserver.py`, the top of `main()` down to the loop: which
   store each flag turns on, and how a datagram is read and answered.
2. `framing.py`, `handshake.py`, `worlddoor.py`, `worldchannel.py`: from the
   first datagram to the lobby's selector channel.
3. The lobby: `charrecords.py`, `peerrecords.py`, `userlist.py`,
   `worldpose.py`, `lobbycmd.py`, `arenamaps.py`.
4. Battletables: `tablerecords.py`, `tableverbs.py`, `questlist.py`,
   `advertise.py`.
5. A battle: `gamemsg.py`, `briefingroom.py`, `teamdist.py`, `battleroom.py`,
   `arenadata.py`, `p2pbattle.py`, `fielditems.py`.

### The facade

`tools/docudp.py` is where the whole responder used to live. It is now a thin
module that imports the `docworld` package and forwards `docudp.<name>` reads
and writes to the module that owns the name, so the tests written as
`import docudp as D` keep working, and a test that rebinds a name
(`D.host_for = fake`) reaches the code that calls it. New code should import
from `docworld` directly. `tools/facade_rebind_check.py` proves the
forwarding for every name.

### How docworld/ was made

`docworld/` was generated from the single-file `docudp.py` by
`tools/split/split_docudp.py`, following `tools/split/split_docudp_map.txt`
(which module each top-level name goes to). Every function, class and global
moved as it was, with the comments above it; references across modules are
qualified with the owning module's name. The tool is deterministic, so a
change made to the single file can be carried over by running it again on
that file:

```
git show <last commit before the split>:tools/docudp.py > docudp_flat.py
# apply the change to docudp_flat.py, then
python tools/split/split_docudp.py --src docudp_flat.py \
    --map tools/split/split_docudp_map.txt \
    --out tools/docworld --facade tools/docudp.py
```

A new top-level name has to be added to the map first; the tool refuses to
write while anything is unmapped. Once work lands in `docworld/` directly,
this route closes.

## Running the checks

```
python check.py --selftest     # the hygiene scanner can fail (positive controls)
python check.py                # nothing private or proprietary in the tree
python tools/doc_run_all.py    # every self-test; -k <substring> picks a few
```

The end-to-end scripts are run one at a time, each from any directory:
`python tools/doc_battle_e2e.py`, `python tests/test_doc_session_nat.py`, and
so on. Each starts `docudp.py` on a loopback port and takes from a few
seconds to two minutes.

A new self-test is registered by hand in `tools/doc_run_all.py`. The list is
explicit on purpose: a suite that is not registered does not run.

## What a pull request needs

- One topic per pull request, with a subject line that says what the server
  now does differently.
- The checks above green, and a self-test for behaviour that can be pinned
  offline. A change to what a suite pins updates the suite in the same pull
  request.
- No Square Enix content: no level data, client tables, captured server
  blobs, art or text from the game or its guides, and no captured packets in
  tests. Tables that come from the user's own copy stay out of the tree
  (`.gitignore` lists them). Data taken from a published guide names its
  source in a comment and quotes nothing.
- Nothing private: no real addresses or hostnames, no member names or ids.
- Plain prose in comments and docs: say what the code does and why.
- A value that exists because the real client needs it keeps a comment
  naming the client routine or the observation it came from. Many fields in
  this protocol were found to work before they were understood, and a reader
  cannot tell those from mistakes without that note.
