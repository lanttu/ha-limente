"""Decrypt Telink mesh traffic from an Android btsnoop_hci.log.

Usage:
  uv run python tools/decrypt_snoop.py btsnoop_hci.log --mac AA:BB:CC:DD:EE:FF \
      --cred telink_mesh1:123 --cred MyMesh:secret

Needs tshark (brew install wireshark). Finds the login handshake (write to the
Pair characteristic + its read response), checks which credential pair matches,
derives the session key and decrypts every command write and status
notification that follows. Handle numbers for the characteristics are taken
from the ATT traffic where possible; override with --cmd-handle/--pair-handle/
--status-handle (hex) if discovery was not captured.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from limente_ble import telink as tl  # noqa: E402

UUID_TAIL = {tl.PAIR_UUID[-4:]: "pair", tl.COMMAND_UUID[-4:]: "cmd", tl.STATUS_UUID[-4:]: "status"}


def tshark_json(path: str) -> list[dict]:
    out = subprocess.run(
        ["tshark", "-r", path, "-Y", "btatt", "-T", "json",
         "-e", "frame.number", "-e", "frame.time_relative", "-e", "btatt.opcode",
         "-e", "btatt.handle", "-e", "btatt.value", "-e", "btatt.uuid128", "-e", "bthci_acl.src.bd_addr"],
        check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def field(layer: dict, name: str):
    v = layer.get(name)
    return v[0] if isinstance(v, list) and v else v


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--mac", required=True, help="light's Bluetooth MAC")
    ap.add_argument("--cred", action="append", default=[], help="name:password, repeatable")
    ap.add_argument("--pair-handle", type=lambda s: int(s, 16))
    ap.add_argument("--cmd-handle", type=lambda s: int(s, 16))
    ap.add_argument("--status-handle", type=lambda s: int(s, 16))
    a = ap.parse_args()
    creds = [(c.split(":", 1)[0], c.split(":", 1)[1]) for c in a.cred] or [(tl.DEFAULT_MESH_NAME, tl.DEFAULT_MESH_PASSWORD)]

    handles = {}
    if a.pair_handle: handles[a.pair_handle] = "pair"
    if a.cmd_handle: handles[a.cmd_handle] = "cmd"
    if a.status_handle: handles[a.status_handle] = "status"

    frames = tshark_json(a.log)
    # Pass 1: learn handle -> characteristic from Read By Type / Find Info responses.
    for fr in frames:
        layer = fr["_source"]["layers"]
        uuid = field(layer, "btatt.uuid128"); handle = field(layer, "btatt.handle")
        if uuid and handle and uuid.replace(":", "")[-4:].lower() in UUID_TAIL:
            h = int(handle, 16) if isinstance(handle, str) and handle.startswith("0x") else int(handle)
            handles.setdefault(h, UUID_TAIL[uuid.replace(":", "")[-4:].lower()])
    print("handles:", {hex(k): v for k, v in handles.items()})

    key = None; session_random = None
    for fr in frames:
        layer = fr["_source"]["layers"]
        op = field(layer, "btatt.opcode"); handle = field(layer, "btatt.handle"); val = field(layer, "btatt.value")
        if not (op and val):
            continue
        op = int(op, 16); h = int(handle, 16) if handle else None
        data = bytes.fromhex(val.replace(":", ""))
        kind = handles.get(h)
        t = field(layer, "frame.time_relative"); n = field(layer, "frame.number")
        if kind == "pair" and op in (0x12, 0x52) and data[0] == 0x0C:  # write request/command
            session_random = data[1:9]
            match = [c for c in creds if tl.verify_pair_packet(data, *c)]
            print(f"[{n} {t}s] LOGIN request rand={session_random.hex()} credentials match: {match or 'NONE of the given'}")
            cred = match[0] if match else None
        elif kind == "pair" and op == 0x0B and session_random and data[0] == tl.PAIR_OK:  # read response
            if cred:
                key = tl.make_session_key(*cred, session_random, data[1:9])
                print(f"[{n} {t}s] LOGIN ok, session key {key.hex()}")
            else:
                print(f"[{n} {t}s] LOGIN ok but credentials unknown; cannot decrypt this session")
                key = None
        elif kind == "cmd" and op in (0x12, 0x52) and key:
            plain = tl.decrypt_command_packet(key, a.mac, data)
            print(f"[{n} {t}s] CMD  {data.hex(' ')}\n      -> {tl.parse_plain(plain) if plain else 'checksum failed (wrong --mac?)'}")
        elif kind == "status" and op == 0x1B and key:  # handle value notification
            plain = tl.decrypt_notification(key, a.mac, data)
            print(f"[{n} {t}s] NTFY {data.hex(' ')}\n      -> {plain[7:].hex(' ') if plain else 'checksum failed'}")


if __name__ == "__main__":
    main()
