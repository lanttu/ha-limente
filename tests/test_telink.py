"""Protocol tests using packets from a real capture of the Limente iOS app."""
import pytest

from custom_components.limente import telink as tl

NAME, PASSWORD = "Srm@7478@a", "475869"
MAC = "AA:67:13:C3:01:AC"
LOGIN_REQ = bytes.fromhex("0c482d5ecb6dc9c9b25c52194699f81e19")
LOGIN_RSP = bytes.fromhex("0d000f6d476344cdc7cae80b08c2d259c6")
SESSION_KEY = bytes.fromhex("9826a32cd33f66b7341a0d237177cf78")


def test_login_request_matches_credentials():
    assert tl.verify_pair_packet(LOGIN_REQ, NAME, PASSWORD)
    assert not tl.verify_pair_packet(LOGIN_REQ, NAME, "475860")
    assert tl.make_pair_packet(NAME, PASSWORD, LOGIN_REQ[1:9]) == LOGIN_REQ


def test_session_key():
    assert LOGIN_RSP[0] == tl.PAIR_OK
    assert tl.make_session_key(NAME, PASSWORD, LOGIN_REQ[1:9], LOGIN_RSP[1:9]) == SESSION_KEY


@pytest.mark.parametrize(
    ("packet", "dest", "opcode", "params"),
    [
        ("ca8e0775bc04c7261204334ff1a63a7588691676", 0xAC, tl.OP_USER_ALL, "1076"),
        ("cb8e072abaf124b65572394b22d529e7196d2bcc", 0xE9, tl.OP_USER_ALL, "1076"),
        ("cc8e07769ab7e384b1115a4d26b045e787693a2c", 0xAC, tl.OP_ON_OFF, "0001"),
        ("cd8e076f03e07d254a93b3c6b9ecb2c70aa9f4e5", 0xAC, tl.OP_ON_OFF, "0101"),
        ("ce8e076dd865ccf41c6fe592cf0d246b7c854010", 0xAC, tl.OP_BRIGHTNESS, "49"),
    ],
)
def test_decrypt_app_commands(packet, dest, opcode, params):
    raw = bytes.fromhex(packet)
    plain = tl.decrypt_command_packet(SESSION_KEY, MAC, raw)
    assert plain is not None
    fields = tl.parse_plain(plain)
    assert fields["dest"] == dest
    assert fields["opcode"] == opcode
    assert fields["vendor"] == "1102"
    assert plain[5:].rstrip(b"\x00").hex() == params
    # Rebuilding with the same sequence number reproduces the app's bytes exactly.
    rebuilt = tl.make_command_packet(SESSION_KEY, MAC, dest, opcode, bytes.fromhex(params), seq=raw[:3])
    assert rebuilt == raw


def test_mac_low4_gives_same_packets():
    raw = bytes.fromhex("cc8e07769ab7e384b1115a4d26b045e787693a2c")
    assert tl.make_command_packet(SESSION_KEY, "ac01c313", 0xAC, tl.OP_ON_OFF, b"\x00\x01", seq=raw[:3]) == raw


def test_decrypt_online_status_notification():
    raw = bytes.fromhex("88f3d20000e0320900fb4f7362ca9de15add1a1a")
    plain = tl.decrypt_notification(SESSION_KEY, MAC, raw)
    assert plain is not None
    note = tl.parse_notification(plain)
    assert note["opcode"] == tl.OP_ONLINE_STATUS
    assert note["vendor"] == tl.VENDOR_ID
    entries = tl.parse_online_status(note["params"])
    assert entries == [
        {"mesh_address": 0xAC, "online": True, "on": True, "brightness": 0x4A, "reserve": 0xFF},
        {"mesh_address": 0xE9, "online": True, "on": False, "brightness": 0, "reserve": 0xFF},
    ]


def test_decrypt_device_info_notification():
    raw = bytes.fromhex("08d3e0ac00d418af06199b17c50ee2ba5f4c5816")
    note = tl.parse_notification(tl.decrypt_notification(SESSION_KEY, MAC, raw))
    assert note["opcode"] == tl.OP_USER_ALL_NOTIFY
    assert note["src"] == 0xAC
    assert tl.parse_device_info(note["params"]) == {"mesh_address": 0xAC, "product_uuid": 0x3101, "mac": MAC}


def test_bad_mic_returns_none():
    raw = bytearray.fromhex("88f3d20000e0320900fb4f7362ca9de15add1a1a")
    raw[-1] ^= 0xFF
    assert tl.decrypt_notification(SESSION_KEY, MAC, bytes(raw)) is None


@pytest.mark.parametrize(
    "hexdata",
    [
        # macOS: both records concatenated, second keeps its company id
        "11 02 ac 01 c3 13 11 02 ac 01 c3 13 01 31 01 ac 00 06 00 56 36 2e 4d 06 58 08 09 0a 0b 0c 0d 0e 0f",
        # BlueZ: only the scan response record payload
        "11 02 ac 01 c3 13 01 31 01 ac 00 06 00 56 36 2e 4d 06 58 08 09 0a 0b 0c 0d 0e 0f",
    ],
)
def test_parse_advertisement(hexdata):
    adv = tl.parse_advertisement(bytes.fromhex(hexdata), company_id=tl.VENDOR_ID)
    assert adv["mesh_uuid"] == tl.VENDOR_ID
    assert adv["mac_low4"] == "ac01c313"
    assert adv["product_uuid"] == 0x3101
    assert adv["mesh_address"] == 0xAC


def test_parse_advertisement_rejects_other_vendors():
    assert tl.parse_advertisement(b"\x01\x02\x03", company_id=0x004C) is None
    assert tl.parse_advertisement(bytes.fromhex("11 02 ac 01"), company_id=tl.VENDOR_ID) is None
