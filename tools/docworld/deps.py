"""The imports every module shares, and the optional cipher (doc_kelcrypt)."""
import argparse
import datetime
import math
import os
import select
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ipaddress as _ipaddress

import doc_charastore
import doc_playtime
import doc_npc
import doc_novice
import doc_missions
import doc_field
import doc_npc_spawn
import doc_npcquests
import doc_rank
import doc_stats
import doc_shop
import doc_trade
import doc_chat
import doc_unit
import doc_gear
import doc_magic
import doc_items
try:
    import doc_kelcrypt                      # the client's own cipher, carved out
    _KELCRYPT = doc_kelcrypt.available()
except Exception:                            # blob or interpreter missing -> log-only
    doc_kelcrypt = None
    _KELCRYPT = False
