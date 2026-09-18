"""Config flow and light tests against a fake mesh node."""
from __future__ import annotations

import asyncio
from datetime import timedelta
import time
from unittest.mock import patch

from bleak import BleakError
import pytest

from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_fire_time_changed

from custom_components.limente import telink as tl
from custom_components.limente.const import (
    COMMAND_SPACING,
    CONF_MESH_NAME,
    CONF_MESH_PASSWORD,
    DEVICE_TIMEOUT,
    DOMAIN,
    STATUS_INTERVAL,
)

from .fake_ble import ADV_MFR, NODE_ADDR, NODE_MAC, OTHER_ADDR, FakeMeshNode, ble_device

MESH_NAME, MESH_PASSWORD = tl.DEFAULT_MESH_NAME, tl.DEFAULT_MESH_PASSWORD


def service_info(address: str = NODE_MAC, name: str = MESH_NAME) -> BluetoothServiceInfoBleak:
    return BluetoothServiceInfoBleak(
        name=name, address=address, rssi=-60, manufacturer_data={0x0211: ADV_MFR},
        service_data={}, service_uuids=[], source="local", device=ble_device(address),
        advertisement=None, connectable=True, time=time.monotonic(), tx_power=None,
    )


@pytest.fixture
def node():
    return FakeMeshNode(MESH_NAME, MESH_PASSWORD)


@pytest.fixture
def mock_ble(node):
    """Patch HA's bluetooth helpers and the connection factory."""
    callbacks = []

    def register(hass, cb, matcher, mode):
        callbacks.append(cb)
        return lambda: None

    async def establish(client_class, device, name, disconnected_callback=None, **kwargs):
        node.disconnected_callback = disconnected_callback
        node.is_connected = True
        return node

    with (
        patch("homeassistant.components.bluetooth.async_discovered_service_info", return_value=[service_info()]),
        patch("homeassistant.components.bluetooth.async_register_callback", side_effect=register),
        patch("homeassistant.components.bluetooth.async_ble_device_from_address", return_value=ble_device()),
        patch("custom_components.limente.mesh.establish_connection", side_effect=establish),
    ):
        yield callbacks


async def _advance(hass: HomeAssistant, seconds: float = 1) -> None:
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=seconds))
    await hass.async_block_till_done()


# ----------------------------------------------------------------------------- config flow


async def test_user_flow_creates_entry(hass: HomeAssistant, mock_ble, node) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    assert result["type"] == "form"
    assert result["description_placeholders"]["found"] == MESH_NAME

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MESH_NAME: MESH_NAME, CONF_MESH_PASSWORD: MESH_PASSWORD}
    )
    assert result["type"] == "create_entry"
    assert result["title"] == f"Limente mesh {MESH_NAME}"
    assert result["data"] == {CONF_MESH_NAME: MESH_NAME, CONF_MESH_PASSWORD: MESH_PASSWORD}
    assert result["result"].unique_id == MESH_NAME
    assert node.disconnect_calls >= 1  # validation disconnects again


async def test_user_flow_wrong_password(hass: HomeAssistant, mock_ble) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MESH_NAME: MESH_NAME, CONF_MESH_PASSWORD: "000000"}
    )
    assert result["type"] == "form"
    assert result["errors"] == {"base": "invalid_auth"}


async def test_user_flow_unknown_mesh_name(hass: HomeAssistant, mock_ble) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MESH_NAME: "SomethingElse", CONF_MESH_PASSWORD: MESH_PASSWORD}
    )
    assert result["type"] == "form"
    assert result["errors"] == {"base": "no_devices_found"}


async def test_user_flow_nothing_in_range(hass: HomeAssistant) -> None:
    with patch("homeassistant.components.bluetooth.async_discovered_service_info", return_value=[]):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    assert result["type"] == "abort"
    assert result["reason"] == "no_devices_found"


async def test_bluetooth_discovery_flow(hass: HomeAssistant, mock_ble) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "bluetooth"}, data=service_info()
    )
    assert result["type"] == "form"
    assert result["step_id"] == "user"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_MESH_NAME: MESH_NAME, CONF_MESH_PASSWORD: MESH_PASSWORD}
    )
    assert result["type"] == "create_entry"


async def test_bluetooth_discovery_ignores_other_devices(hass: HomeAssistant, mock_ble) -> None:
    info = service_info()
    info.manufacturer_data = {0x004C: b"\x01\x02"}
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "bluetooth"}, data=info)
    assert result["type"] == "abort"
    assert result["reason"] == "not_supported"


# ----------------------------------------------------------------------------- lights


async def _setup_entry(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=MESH_NAME, title="Limente",
        data={CONF_MESH_NAME: MESH_NAME, CONF_MESH_PASSWORD: MESH_PASSWORD},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    await _advance(hass)  # fires the scheduled connect
    return entry


async def test_lights_connect_and_control(hass: HomeAssistant, mock_ble, node) -> None:
    await _setup_entry(hass)
    # Connected, logged in, notifications enabled, initial status query sent.
    assert node.session_key is not None
    assert node.notify_cb is not None
    assert node.commands[0]["opcode"] == tl.OP_STATUS_QUERY

    # The node from the advertisement and the one only seen in the status report both exist.
    ac = hass.states.get("light.limente_dimmer_ac")
    e9 = hass.states.get("light.limente_dimmer_e9")
    assert ac is not None and e9 is not None
    assert ac.state == "on"
    assert ac.attributes["brightness"] == round(74 * 255 / 100)
    assert ac.attributes["mesh_address"] == NODE_ADDR
    assert e9.state == "off"

    # Turn the other dimmer on at 40% -> D0 on then D2 40, addressed through the mesh.
    await hass.services.async_call(
        "light", "turn_on", {ATTR_ENTITY_ID: "light.limente_dimmer_e9", "brightness": 102}, blocking=True
    )
    await hass.async_block_till_done()
    sent = [c for c in node.commands[1:] if c["opcode"] != tl.OP_USER_ALL]  # ignore device-info queries
    assert [(c["dest"], c["opcode"], c["params_bytes"][:1]) for c in sent] == [
        (OTHER_ADDR, tl.OP_ON_OFF, b"\x01"),
        (OTHER_ADDR, tl.OP_BRIGHTNESS, b"\x28"),
    ]
    e9 = hass.states.get("light.limente_dimmer_e9")
    assert e9.state == "on"
    assert e9.attributes["brightness"] == round(40 * 255 / 100)

    # Turn the connected dimmer off.
    await hass.services.async_call("light", "turn_off", {ATTR_ENTITY_ID: "light.limente_dimmer_ac"}, blocking=True)
    await hass.async_block_till_done()
    assert node.commands[-1]["dest"] == NODE_ADDR
    assert node.commands[-1]["opcode"] == tl.OP_ON_OFF
    assert node.commands[-1]["params_bytes"][0] == 0
    # The mesh-only node got its MAC through the device-info reply.
    assert e9.attributes["mesh_address"] == OTHER_ADDR
    assert hass.states.get("light.limente_dimmer_ac").state == "off"


async def test_external_change_is_pushed(hass: HomeAssistant, mock_ble, node) -> None:
    await _setup_entry(hass)
    node.state[OTHER_ADDR] = [True, 55]
    node.send_online_status()
    await hass.async_block_till_done()
    e9 = hass.states.get("light.limente_dimmer_e9")
    assert e9.state == "on"
    assert e9.attributes["brightness"] == round(55 * 255 / 100)


async def test_disconnect_marks_unavailable_and_reconnects(hass: HomeAssistant, mock_ble, node) -> None:
    await _setup_entry(hass)
    assert hass.states.get("light.limente_dimmer_ac").state == "on"
    await node.disconnect()  # fires the disconnected callback
    await hass.async_block_till_done()
    assert hass.states.get("light.limente_dimmer_ac").state == "unavailable"
    await _advance(hass, 5)
    assert node.is_connected
    assert hass.states.get("light.limente_dimmer_ac").state == "on"


async def test_idle_nodes_stay_available(hass: HomeAssistant, mock_ble, node) -> None:
    """A node that has been silent longer than DEVICE_TIMEOUT must still take commands
    while the mesh reports it online. The connected node stops advertising, so this is
    the normal case for it."""
    entry = await _setup_entry(hass)
    mesh = entry.runtime_data
    stale = time.monotonic() - DEVICE_TIMEOUT - 1
    for device in mesh.devices.values():
        device.last_seen = stale
    assert mesh.device_available(mesh.devices[NODE_ADDR])
    assert mesh.device_available(mesh.devices[OTHER_ADDR])

    before = len(node.commands)
    await hass.services.async_call("light", "turn_off", {ATTR_ENTITY_ID: "light.limente_dimmer_ac"}, blocking=True)
    await hass.async_block_till_done()
    assert len(node.commands) > before, "HA dropped the call because the entity was unavailable"
    assert node.commands[-1]["dest"] == NODE_ADDR
    assert node.commands[-1]["opcode"] == tl.OP_ON_OFF


async def test_mesh_offline_report_marks_unavailable(hass: HomeAssistant, mock_ble, node) -> None:
    await _setup_entry(hass)
    assert hass.states.get("light.limente_dimmer_e9").state == "off"

    node.offline.add(OTHER_ADDR)
    node.send_online_status()
    await hass.async_block_till_done()
    assert hass.states.get("light.limente_dimmer_e9").state == "unavailable"
    assert hass.states.get("light.limente_dimmer_ac").state == "on"

    before = len(node.commands)
    await hass.services.async_call("light", "turn_on", {ATTR_ENTITY_ID: "light.limente_dimmer_e9"}, blocking=True)
    await hass.async_block_till_done()
    assert len(node.commands) == before

    node.offline.discard(OTHER_ADDR)
    node.send_online_status()
    await hass.async_block_till_done()
    assert hass.states.get("light.limente_dimmer_e9").state == "off"


async def test_periodic_status_query(hass: HomeAssistant, mock_ble, node) -> None:
    await _setup_entry(hass)
    queries = lambda: [c for c in node.commands if c["opcode"] == tl.OP_STATUS_QUERY]  # noqa: E731
    assert len(queries()) == 1

    async def tick() -> None:
        # The query is written from a background task that first waits out the
        # command spacing, so give it real time to land.
        await _advance(hass, STATUS_INTERVAL + 1)
        await asyncio.sleep(COMMAND_SPACING + 0.05)
        await hass.async_block_till_done()

    await tick()
    assert len(queries()) == 2
    assert queries()[-1]["dest"] == tl.ADDR_BROADCAST
    await tick()
    assert len(queries()) == 3

    # No more queries once the connection is gone.
    await node.disconnect()
    await hass.async_block_till_done()
    node.commands.clear()
    with patch("custom_components.limente.mesh.establish_connection", side_effect=BleakError("gone")):
        await tick()
    assert queries() == []


async def test_setup_not_ready_without_nodes(hass: HomeAssistant, node) -> None:
    with (
        patch("homeassistant.components.bluetooth.async_discovered_service_info", return_value=[]),
        patch("homeassistant.components.bluetooth.async_register_callback", return_value=lambda: None),
    ):
        entry = MockConfigEntry(domain=DOMAIN, unique_id=MESH_NAME,
                                data={CONF_MESH_NAME: MESH_NAME, CONF_MESH_PASSWORD: MESH_PASSWORD})
        entry.add_to_hass(hass)
        assert not await hass.config_entries.async_setup(entry.entry_id)
        assert entry.state.name == "SETUP_RETRY"
