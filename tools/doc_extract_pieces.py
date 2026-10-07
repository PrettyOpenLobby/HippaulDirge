#!/usr/bin/env python3
"""Dirge of Cerberus Online: which MAP PIECES cover which ground (2026-10-06).

Kind 2 (battle spawn) and kind 25 (down / respawn point) carry two map-piece
numbers, M0 / M1 (payload bytes the client writes to [chan+0x444/0x445]); on a
(re)spawn ev2045.battlefield loads exactly those two mNNN pieces of the zone,
and the others only stream in when the player crosses a trigger. One pair per
zone left a spawn outside both pieces standing on unloaded ground (live
10-06: Jungle team 1's start (2590, -1240) lies only in m004, we sent (1, 3)).
Static RE + measurement: scratchpad re-capdrop/pieces.py.

This reads each arena zone's data/zone/zNNN/mXXX/model.rfd (16-byte records,
f32 x / y / z / w; m000 and m255 skipped) and writes a coarse x/z grid of
vertex counts per piece, so docworld.arenamaps.spawn_bmap can pick the pieces
around a point. The output is the game's own level data, so it is not shipped:
run it on your own copy.

    python doc_extract_pieces.py <data/zone dir> [out.json]
"""
import json
import math
import os
import struct
import sys

CELL = 100.0                 # grid cell, world units
ZONES = range(201, 238)      # the arenas
LIMIT_XZ, LIMIT_Y = 8000.0, 3000.0
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "doc_map_pieces.json")


def points(path):
    """(x, z) of every plausible vertex record in a model.rfd."""
    with open(path, "rb") as f:
        d = f.read()
    for k in range(len(d) // 16):
        x, y, z, _w = struct.unpack_from("<4f", d, 16 * k)
        if not all(math.isfinite(v) for v in (x, y, z)):
            continue
        if abs(x) >= LIMIT_XZ or abs(z) >= LIMIT_XZ or abs(y) >= LIMIT_Y:
            continue
        if abs(x) <= 1e-3 or abs(z) <= 1e-3:
            continue
        yield x, z


def zone_grid(zdir):
    """{piece number: {"gx,gz": count}} for one zone directory."""
    out = {}
    for m in sorted(os.listdir(zdir)):
        if not (m.startswith("m") and m[1:].isdigit()):
            continue
        num = int(m[1:])
        rfd = os.path.join(zdir, m, "model.rfd")
        if num in (0, 255) or not os.path.exists(rfd):
            continue
        cells = {}
        for x, z in points(rfd):
            k = "%d,%d" % (math.floor(x / CELL), math.floor(z / CELL))
            cells[k] = cells.get(k, 0) + 1
        if cells:
            out[str(num)] = cells
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    root, out = argv[1], (argv[2] if len(argv) > 2 else OUT)
    data = {"cell": CELL, "zones": {}}
    for zone in ZONES:
        zdir = os.path.join(root, "z%03d" % zone)
        if os.path.isdir(zdir):
            g = zone_grid(zdir)
            if g:
                data["zones"][str(zone)] = g
                print("z%03d: pieces %s" % (zone, sorted(int(p) for p in g)))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))
    print("wrote %s (%d zone(s))" % (out, len(data["zones"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
