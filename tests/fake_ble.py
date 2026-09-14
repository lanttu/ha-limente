"""A fake Telink mesh node behind a BleakClient-like interface."""
from __future__ import annotations

import asyncio
import os
import struct
from typing import Any

from bleak.backends.device import BLEDevice

from custom_components.limente import telink as tl

NODE_MAC = "AA:67:13:C3:01:AC"
NODE_ADDR = 0xAC
OTHER_ADDR = 0xE9
ADV_MFR = bytes.fromhex("11 02 ac 01 c3 13 01 31 01 ac 00 06 00 56 36 2e 4d 06 58 08 09 0a 0b 0c 0d 0e 0f")


def ble_device(address: str = NODE_MAC) -> BLEDevice:
    return BLEDevice(address, "Srm@7478@a", {})


class FakeMeshNode:
    """Understands the login handshake and answers commands with DC reports."""

    def __init__(self, mesh_name: str, mesh_password: str, mac: str = NODE_MAC) -> None:
        self.mesh_name, self.mesh_password, self.mac = mesh_name, mesh_password, mac
        self.session_key: bytes | None = None
        self._pair_reply = b"\x0e"
        self.commands: list[dict] = []
        self.notify_cb = None
        self.state = {NODE_ADDR: [True, 74], OTHER_ADDR: [False, 0]}  # addr -> [on, brightness]
        self.disconnected_callback = None
        self.is_connected = True
        self.disconnect_calls = 0

    # --- GATT surface used by the integration
    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = False) -> None:
        data = bytes(data)
        if uuid == tl.PAIR_UUID:
            if tl.verify_pair_packet(data, self.mesh_name, self.mesh_password):
                resp_random = os.urandom(8)
                self.session_key = tl.make_session_key(self.mesh_name, self.mesh_password, data[1:9], resp_random)
                self._pair_reply = b"\x0d" + resp_random + b"\x00" * 8
            else:
                self._pair_reply = b"\x0e" + b"\x00" * 16
        elif uuid == tl.STATUS_UUID:
            assert data == b"\x01"
        elif uuid == tl.COMMAND_UUID:
            assert self.session_key
            plain = tl.decrypt_command_packet(self.session_key, self.mac, data)
            assert plain is not None, "bad MIC on command"
            cmd = tl.parse_plain(plain)
            cmd["params_bytes"] = plain[5:]
            self.commands.append(cmd)
            self._apply(cmd)
        else:
            raise AssertionError(f"unexpected write to {uuid}")

    async def read_gatt_char(self, uuid: str) -> bytes:
        assert uuid == tl.PAIR_UUID
        return self._pair_reply

    async def start_notify(self, uuid: str, cb) -> None:
        assert uuid == tl.STATUS_UUID
        self.notify_cb = cb

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        self.is_connected = False
        if self.disconnected_callback:
            self.disconnected_callback(self)

    # --- behaviour
    def _apply(self, cmd: dict) -> None:
        dest, op, p = cmd["dest"], cmd["opcode"], cmd["params_bytes"]
        targets = list(self.state) if dest in (0, 0xFFFF) else [dest]
        for addr in targets:
            if addr not in self.state:
                continue
            if op == tl.OP_ON_OFF:
                self.state[addr][0] = bool(p[0])
                if not p[0]:
                    self.state[addr][1] = 0
                elif self.state[addr][1] == 0:
                    self.state[addr][1] = 100
            elif op == tl.OP_BRIGHTNESS:
                self.state[addr][0] = True
                self.state[addr][1] = p[0]
        if op in (tl.OP_ON_OFF, tl.OP_BRIGHTNESS, tl.OP_STATUS_QUERY):
            self.send_online_status()
        elif op == tl.OP_USER_ALL and p[:2] == b"\x10\x76":
            self.send_device_info(dest if dest else NODE_ADDR)

    def _notify(self, src: int, opcode: int, params: bytes) -> None:
        assert self.session_key and self.notify_cb
        seq = os.urandom(3)
        head = seq + struct.pack("<H", src)
        payload = (bytes([opcode]) + tl.VENDOR_BYTES + params).ljust(13, b"\x00")
        nonce = tl.mac_bytes(self.mac)[:3] + head
        mic = tl.make_checksum(self.session_key, nonce, payload)[:2]
        self.notify_cb(None, bytearray(head + mic + tl.crypt_payload(self.session_key, nonce, payload)))

    def send_online_status(self) -> None:
        params = b""
        for addr, (on, br) in self.state.items():
            params += bytes([addr, 0x60, br if on else 0, 0xFF])
        self._notify(0, tl.OP_ONLINE_STATUS, params[:10])

    def send_device_info(self, addr: int) -> None:
        mac = self.mac if addr == NODE_ADDR else "AA:67:12:93:00:E9"
        self._notify(addr, tl.OP_USER_ALL_NOTIFY, bytes([addr, 0x76, 0x01, 0x31]) + bytes(reversed(bytes.fromhex(mac.replace(":", "")))))
