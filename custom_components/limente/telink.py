"""Telink BLE mesh ("tlmesh") protocol as used by Sunricher EasyThings based
products such as Limente SMART dimmers.

Byte layouts follow the Telink SmartLight Android SDK. Telink runs AES-128 on
byte-reversed inputs and reverses the output, hence the reversals in ``_aes``.
Verified against a live capture of the Limente iOS app.
"""
from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVICE_UUID = "00010203-0405-0607-0809-0a0b0c0d1910"
STATUS_UUID = "00010203-0405-0607-0809-0a0b0c0d1911"   # notify: status reports
COMMAND_UUID = "00010203-0405-0607-0809-0a0b0c0d1912"  # write: encrypted commands
OTA_UUID = "00010203-0405-0607-0809-0a0b0c0d1913"      # firmware update, never write
PAIR_UUID = "00010203-0405-0607-0809-0a0b0c0d1914"     # login handshake

# Telink factory defaults for an unprovisioned device.
TELINK_FACTORY_NAME = "telink_mesh1"
TELINK_FACTORY_PASSWORD = "123"

# Default network of the Limente / Sunricher EasyThings app. The light
# advertises its current mesh name as the local name and reports it as the
# Device Information "Manufacturer Name String".
DEFAULT_MESH_NAME = "Srm@7478@a"
DEFAULT_MESH_PASSWORD = "475869"

VENDOR_ID = 0x0211  # Telink Semiconductor; little-endian in packets and adverts
VENDOR_BYTES = VENDOR_ID.to_bytes(2, "little")

# Pair characteristic reply codes.
PAIR_OK = 0x0D
PAIR_BAD_CREDENTIALS = 0x0E

# Opcodes (Telink Opcode enum; params as used by the EasyThings app).
OP_ON_OFF = 0xD0          # params: 01 00 00 = on, 00 00 00 = off
OP_BRIGHTNESS = 0xD2      # params: level 0..100
OP_STATUS_QUERY = 0xDA    # params: 10
OP_STATUS_RESPONSE = 0xDB
OP_ONLINE_STATUS = 0xDC   # notification: 4-byte entries addr,sn,brightness,reserve
OP_COLOR = 0xE2           # params: 04 r g b = RGB, 05 x = colour temperature 0..100
OP_SET_ADDRESS = 0xE0
OP_KICK_OUT = 0xE3        # factory reset, never send by accident
OP_GET_STATE = 0xC8
OP_USER_ALL = 0xEA        # vendor extension; params 10 76 = get device info
OP_USER_ALL_NOTIFY = 0xEB # reply: addr 76 productUUID(2) MAC(6, device order)

# Mesh addresses.
ADDR_CONNECTED = 0x0000   # the node we are connected to
ADDR_BROADCAST = 0xFFFF   # every node

MAX_PARAMS = 10


def _pad16(data: bytes) -> bytes:
    return bytes(data).ljust(16, b"\x00")


def _aes(key: bytes, value: bytes) -> bytes:
    """AES-128-ECB on reversed key/value, output reversed (Telink convention)."""
    if len(key) != 16 or len(value) != 16:
        raise ValueError("AES key and block must be 16 bytes")
    enc = Cipher(algorithms.AES(bytes(reversed(key))), modes.ECB()).encryptor()
    return bytes(reversed(enc.update(bytes(reversed(value))) + enc.finalize()))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _name_pass_key(mesh_name: str | bytes, mesh_password: str | bytes) -> bytes:
    if isinstance(mesh_name, str):
        mesh_name = mesh_name.encode()
    if isinstance(mesh_password, str):
        mesh_password = mesh_password.encode()
    if len(mesh_name) > 16 or len(mesh_password) > 16:
        raise ValueError("mesh name and password are at most 16 bytes")
    return _xor(_pad16(mesh_name), _pad16(mesh_password))


def mac_bytes(mac: str) -> bytes:
    """Nonce MAC bytes in device (little-endian) order.

    Accepts a full 'AA:BB:CC:DD:EE:FF' (reversed to device order) or the
    8 hex digits of the low 4 MAC bytes exactly as they appear in the Telink
    advertisement (already in device order).
    """
    raw = bytes.fromhex(mac.replace(":", "").replace("-", "").replace(" ", ""))
    if len(raw) == 6:
        return bytes(reversed(raw))
    if len(raw) == 4:
        return raw
    raise ValueError(f"bad MAC {mac!r}: need 6 bytes or the 4 advertised bytes")


def make_checksum(key: bytes, nonce: bytes, payload: bytes) -> bytes:
    """CBC-MAC over the payload, IV = nonce + len(payload)."""
    check = _aes(key, _pad16(nonce + bytes([len(payload)])))
    for i in range(0, len(payload), 16):
        check = _aes(key, _xor(check, _pad16(payload[i:i + 16])))
    return check


def crypt_payload(key: bytes, nonce: bytes, payload: bytes) -> bytes:
    """Counter mode: keystream block i = AES(key, [i] + nonce)."""
    out = bytearray()
    for i in range(0, len(payload), 16):
        block = _aes(key, _pad16(bytes([i // 16]) + nonce))
        out += _xor(block, payload[i:i + 16])
    return bytes(out)


def make_pair_packet(mesh_name, mesh_password, session_random: bytes) -> bytes:
    """Login request written to PAIR_UUID: 0x0C | rand(8) | AES(rand, name^pass)[0:8]."""
    if len(session_random) != 8:
        raise ValueError("session random must be 8 bytes")
    enc = _aes(_pad16(session_random), _name_pass_key(mesh_name, mesh_password))
    return b"\x0c" + session_random + enc[:8]


def verify_pair_packet(packet: bytes, mesh_name, mesh_password) -> bool:
    """True if a captured login request was built with these credentials."""
    if len(packet) < 17 or packet[0] != 0x0C:
        return False
    return make_pair_packet(mesh_name, mesh_password, packet[1:9])[9:17] == packet[9:17]


def make_session_key(mesh_name, mesh_password, session_random: bytes, response_random: bytes) -> bytes:
    """Session key = AES(name^pass, session_random | response_random)."""
    if len(session_random) != 8 or len(response_random) != 8:
        raise ValueError("randoms must be 8 bytes")
    return _aes(_name_pass_key(mesh_name, mesh_password), session_random + response_random)


def make_command_packet(session_key: bytes, mac: str, dest: int, opcode: int,
                        params: bytes = b"", seq: bytes | None = None,
                        vendor: bytes = VENDOR_BYTES) -> bytes:
    """Encrypted 20-byte command written to COMMAND_UUID.

    Layout: seq(3) | mic(2) | enc( dest(2 LE) | opcode|0xC0 | vendor(2) | params, padded to 15 )
    Nonce: mac_low4 | 0x01 | seq
    """
    if len(params) > MAX_PARAMS:
        raise ValueError(f"params too long (max {MAX_PARAMS} bytes)")
    seq = seq or os.urandom(3)
    nonce = mac_bytes(mac)[:4] + b"\x01" + seq
    payload = (struct.pack("<H", dest) + bytes([opcode | 0xC0]) + vendor + params).ljust(15, b"\x00")
    mic = make_checksum(session_key, nonce, payload)[:2]
    return seq + mic + crypt_payload(session_key, nonce, payload)


def decrypt_command_packet(session_key: bytes, mac: str, packet: bytes) -> bytes | None:
    """Decrypt a captured command packet (inverse of make_command_packet)."""
    seq, mic = packet[:3], packet[3:5]
    nonce = mac_bytes(mac)[:4] + b"\x01" + seq
    payload = crypt_payload(session_key, nonce, packet[5:])
    if make_checksum(session_key, nonce, payload)[:2] != mic:
        return None
    return payload


def decrypt_notification(session_key: bytes, mac: str, packet: bytes) -> bytes | None:
    """Decrypt a STATUS_UUID notification.

    Layout: seq(3) | src(2) | mic(2) | enc( opcode | vendor(2) | params(10) ).
    Nonce: mac_low4[0:3] | packet[0:5]. Returns seq|src|mic|plain, or None on bad MIC.
    """
    if len(packet) < 8:
        return None
    nonce = mac_bytes(mac)[:3] + packet[:5]
    payload = crypt_payload(session_key, nonce, packet[7:])
    if make_checksum(session_key, nonce, payload)[:2] != packet[5:7]:
        return None
    return packet[:7] + payload


def parse_notification(plain: bytes) -> dict:
    """Split a decrypted notification into src, opcode, vendor and params."""
    return {
        "src": int.from_bytes(plain[3:5], "little"),
        "opcode": plain[7],
        "vendor": int.from_bytes(plain[8:10], "little"),
        "params": plain[10:],
    }


def parse_plain(payload: bytes) -> dict:
    """Split a decrypted command payload into fields."""
    return {
        "dest": struct.unpack("<H", payload[0:2])[0],
        "opcode": payload[2],
        "vendor": payload[3:5].hex(),
        "params": payload[5:].hex(" "),
    }


def parse_advertisement(mfr: bytes, company_id: int | None = None) -> dict | None:
    """Parse Telink manufacturer-specific advertisement data.

    The light sends two manufacturer records with company id 0x0211:
      adv:           meshUUID(2) macLow4(4)
      scan response: meshUUID(2) macLow4(4) productUUID(2) status(1) meshAddress(2) rsv(16)
    BlueZ keeps only the last record per company id; CoreBluetooth concatenates
    both (the second keeps its company id). This handles both shapes.
    """
    if company_id is not None:
        if company_id != VENDOR_ID:
            return None
        data = bytes(mfr)
    else:
        if len(mfr) < 2 or int.from_bytes(mfr[:2], "little") != VENDOR_ID:
            return None
        data = bytes(mfr[2:])
    if len(data) >= 6 + 13 and data[6:8] == VENDOR_BYTES and data[8:12] == data[2:6]:
        data = data[6:]
    if len(data) < 11:
        return None
    return {
        "mesh_uuid": int.from_bytes(data[0:2], "little"),
        "mac_low4": data[2:6].hex(),
        "product_uuid": int.from_bytes(data[6:8], "little"),
        "status": data[8],
        "mesh_address": int.from_bytes(data[9:11], "little"),
        "rsv": data[11:].hex(" "),
    }


def parse_online_status(params: bytes) -> list[dict]:
    """Parse the params of an 0xDC online status report: 4-byte entries."""
    out = []
    for i in range(0, len(params) - 3, 4):
        addr, sn, brightness, reserve = params[i:i + 4]
        if addr == 0 or (addr == 0xFF and brightness == 0xFF):
            break
        out.append({"mesh_address": addr, "online": sn != 0,
                    "on": brightness != 0, "brightness": brightness, "reserve": reserve})
    return out


def parse_device_info(params: bytes) -> dict | None:
    """Parse the 0xEB reply to `EA 10 76`: addr 76 productUUID(2) MAC(6 device order)."""
    if len(params) < 10 or params[1] != 0x76:
        return None
    return {
        "mesh_address": params[0],
        "product_uuid": int.from_bytes(params[2:4], "little"),
        "mac": ":".join(f"{b:02X}" for b in reversed(params[4:10])),
    }
