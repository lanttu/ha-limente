"""Connect to a Limente / Telink mesh light, log in, and send commands.

Run from a normal Terminal window. Get --address and --mac from tools/scan.py.

  uv run python tools/probe.py --address AA:BB:CC:DD:EE:FF login
  uv run python tools/probe.py --address AA:BB:CC:DD:EE:FF on      # --mac only needed if address is a UUID
  uv run python tools/probe.py ... off
  uv run python tools/probe.py ... dim 40            # brightness 0..100
  uv run python tools/probe.py ... cct 50            # colour temperature 0..100 (if supported)
  uv run python tools/probe.py ... status            # ask for 0xDB status response
  uv run python tools/probe.py ... --dest ffff on    # broadcast to whole mesh
  uv run python tools/probe.py ... --dest 00ac on    # one specific dimmer by mesh address (scan.py shows it)
  uv run python tools/probe.py ... raw d2 32         # arbitrary opcode + hex params

Defaults to the Limente app's default network credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

from bleak import BleakClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from limente_ble import telink as tl  # noqa: E402


def build(a: argparse.Namespace) -> tuple[int, bytes]:
    c, args = a.command, a.args
    if c == "on":
        return tl.OP_ON_OFF, b"\x01\x00\x00"
    if c == "off":
        return tl.OP_ON_OFF, b"\x00\x00\x00"
    if c == "dim":
        return tl.OP_BRIGHTNESS, bytes([max(0, min(100, int(args[0])))])
    if c == "cct":
        return tl.OP_COLOR, bytes([0x05, max(0, min(100, int(args[0])))])
    if c == "rgb":
        return tl.OP_COLOR, bytes([0x04] + [int(x) & 0xFF for x in args[:3]])
    if c == "status":
        return tl.OP_STATUS_QUERY, b"\x10"
    if c == "info":
        return tl.OP_USER_ALL, b"\x10\x76"  # reply EB 76 productUUID(2) MAC(6)
    if c == "raw":
        return int(args[0], 16), bytes(int(x, 16) for x in args[1:])
    raise SystemExit(f"unknown command {c}")


async def find_device(address: str, timeout: float = 15.0):
    """Scan until we see the light. Matches the real MAC (use_bdaddr), the
    CoreBluetooth UUID, or the 4 MAC bytes inside the Telink advertisement."""
    from bleak import BleakScanner

    target = address.upper()
    low4 = tl.mac_bytes(address).hex() if len(address.replace(":", "")) in (8, 12) and "-" not in address else None
    found = asyncio.get_event_loop().create_future()

    def cb(dev, adv):
        if found.done():
            return
        if dev.address.upper() == target:
            found.set_result((dev, adv)); return
        for cid, data in adv.manufacturer_data.items():
            p = tl.parse_advertisement(data, company_id=cid)
            if p and low4 and p["mac_low4"] == low4:
                found.set_result((dev, adv)); return

    kwargs = {"cb": {"use_bdaddr": True}} if sys.platform == "darwin" else {}
    try:
        scanner = BleakScanner(cb, **kwargs)
        await scanner.start()
    except Exception:
        scanner = BleakScanner(cb)
        await scanner.start()
    try:
        return await asyncio.wait_for(found, timeout)
    finally:
        await scanner.stop()


async def run(a: argparse.Namespace) -> int:
    print("scanning for", a.address)
    dev, adv = await find_device(a.address)
    parsed = None
    for cid, data in adv.manufacturer_data.items():
        parsed = parsed or tl.parse_advertisement(data, company_id=cid)
    print(f"found {dev.address} rssi={adv.rssi} adv={parsed}")
    mac = a.mac or (parsed["mac_low4"] if parsed else a.address)
    async with BleakClient(dev, timeout=20) as client:
        print("connected", dev.address)
        session_random = os.urandom(8)
        await client.write_gatt_char(tl.PAIR_UUID, tl.make_pair_packet(a.name, a.password, session_random), response=True)
        reply = bytes(await client.read_gatt_char(tl.PAIR_UUID))
        print("pair reply:", reply.hex(" "))
        if reply[0] != tl.PAIR_OK:
            print("login FAILED (0x0e = wrong mesh name/password)")
            return 1
        key = tl.make_session_key(a.name, a.password, session_random, reply[1:9])
        print("login OK, session key", key.hex())

        def on_status(_, data: bytearray):
            raw = bytes(data)
            plain = tl.decrypt_notification(key, mac, raw)
            if plain is None:
                print("notify raw:", raw.hex(" "), "<checksum failed: wrong --mac?>")
                return
            src = int.from_bytes(plain[3:5], "little"); op = plain[7]; params = plain[10:]
            print(f"notify src=0x{src:04x} op=0x{op:02x} params={params.hex(' ')}")
            if op == tl.OP_ONLINE_STATUS:
                for e in tl.parse_online_status(params):
                    print("   ", e)
            elif op == tl.OP_USER_ALL_NOTIFY and params[0] == 0x76:
                mac = ":".join(f"{b:02X}" for b in reversed(params[3:9]))
                print(f"    device info: product_uuid=0x{int.from_bytes(params[1:3], 'little'):04x} mac={mac}")

        await client.write_gatt_char(tl.STATUS_UUID, b"\x01", response=True)
        await client.start_notify(tl.STATUS_UUID, on_status)

        if a.command != "login":
            opcode, params = build(a)
            pkt = tl.make_command_packet(key, mac, a.dest, opcode, params)
            print(f"send dest=0x{a.dest:04x} opcode=0x{opcode:02x} params={params.hex(' ')}")
            await client.write_gatt_char(tl.COMMAND_UUID, pkt, response=False)
        await asyncio.sleep(a.wait)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--address", required=True, help="bleak address / CoreBluetooth id from scan.py")
    p.add_argument("--mac", help="mac_low4 from scan.py, or full MAC")
    p.add_argument("--name", default=tl.DEFAULT_MESH_NAME)
    p.add_argument("--password", default=tl.DEFAULT_MESH_PASSWORD)
    p.add_argument("--dest", type=lambda s: int(s, 16), default=tl.ADDR_CONNECTED, help="hex mesh address, default 0000 = connected node, ffff = all")
    p.add_argument("--wait", type=float, default=4.0, help="seconds to listen for notifications")
    p.add_argument("command", choices=["login", "on", "off", "dim", "cct", "rgb", "status", "info", "raw"])
    p.add_argument("args", nargs="*")
    sys.exit(asyncio.run(run(p.parse_args())))


if __name__ == "__main__":
    main()
