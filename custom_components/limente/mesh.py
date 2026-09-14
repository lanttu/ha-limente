"""One Bluetooth connection into a Telink mesh, shared by all dimmers.

The phone app does the same thing: it connects to whichever node is in range,
logs in, and addresses every other node through the mesh. Status reports
(opcode 0xDC) for all nodes arrive over that single connection.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
import logging
import os
import time
from typing import Any

from bleak import BleakError
from bleak.backends.device import BLEDevice
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from homeassistant.components import bluetooth
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.event import async_call_later

from . import telink as tl
from .const import (
    COMMAND_SPACING,
    CONNECT_TIMEOUT,
    DEVICE_TIMEOUT,
    RECONNECT_MAX,
    RECONNECT_MIN,
    TELINK_MANUFACTURER_ID,
)

_LOGGER = logging.getLogger(__name__)


class LoginFailed(HomeAssistantError):
    """The mesh rejected the name/password."""


@dataclass
class MeshDevice:
    """State of one node in the mesh, keyed by its mesh address."""

    mesh_address: int
    mac: str | None = None
    mac_low4: str | None = None
    product_uuid: int | None = None
    rssi: int | None = None
    is_on: bool = False
    brightness: int = 0            # 0..100 as reported; 0 when off
    last_brightness: int = 100     # last nonzero level, used when turning on
    online: bool = False
    last_seen: float = 0.0         # monotonic time of last advert or status report
    listeners: set[Callable[[], None]] = field(default_factory=set)

    @property
    def name(self) -> str:
        return f"Limente dimmer {self.mesh_address:02X}"

    def touch(self) -> None:
        self.last_seen = time.monotonic()

    def notify(self) -> None:
        for cb in list(self.listeners):
            cb()


def parse_service_info(service_info: bluetooth.BluetoothServiceInfoBleak) -> dict | None:
    """Return the Telink advertisement fields, or None if this is not a mesh node."""
    data = service_info.manufacturer_data.get(TELINK_MANUFACTURER_ID)
    if not data:
        return None
    return tl.parse_advertisement(data, company_id=TELINK_MANUFACTURER_ID)


def nonce_mac_for(device: BLEDevice, adv: dict | None) -> str:
    """MAC bytes for the packet nonce. Linux/ESPHome give the real MAC; on
    macOS the address is a UUID and the advertisement supplies the 4 bytes."""
    if len(device.address.replace(":", "")) == 12 and "-" not in device.address:
        return device.address
    if adv:
        return adv["mac_low4"]
    raise HomeAssistantError("cannot determine the node MAC for encryption")


async def async_login(client: BleakClientWithServiceCache, mesh_name: str, mesh_password: str) -> bytes:
    """Run the pair handshake on an open connection. Returns the session key."""
    session_random = os.urandom(8)
    await client.write_gatt_char(tl.PAIR_UUID, tl.make_pair_packet(mesh_name, mesh_password, session_random), response=True)
    reply = bytes(await client.read_gatt_char(tl.PAIR_UUID))
    if not reply or reply[0] != tl.PAIR_OK:
        raise LoginFailed(f"mesh login rejected (reply {reply.hex()})")
    return tl.make_session_key(mesh_name, mesh_password, session_random, reply[1:9])


async def async_validate_login(hass: HomeAssistant, address: str, mesh_name: str, mesh_password: str) -> None:
    """Connect to one node and check the credentials. Used by the config flow."""
    device = bluetooth.async_ble_device_from_address(hass, address, connectable=True)
    if device is None:
        raise BleakError(f"{address} is not in range")
    client = await establish_connection(BleakClientWithServiceCache, device, f"limente-{address}", max_attempts=2)
    try:
        await async_login(client, mesh_name, mesh_password)
    finally:
        await client.disconnect()


class LimenteMesh:
    """Holds the mesh connection and the state of every known node."""

    def __init__(self, hass: HomeAssistant, mesh_name: str, mesh_password: str) -> None:
        self.hass = hass
        self.mesh_name = mesh_name
        self.mesh_password = mesh_password
        self.devices: dict[int, MeshDevice] = {}
        self.connected = False
        self._client: BleakClientWithServiceCache | None = None
        self._session_key: bytes | None = None
        self._nonce_mac: str | None = None
        self._connected_address: str | None = None
        self._seq = int.from_bytes(os.urandom(3), "little")
        self._send_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._last_send = 0.0
        self._reconnect_delay = RECONNECT_MIN
        self._reconnect_unsub: CALLBACK_TYPE | None = None
        self._connect_task: asyncio.Task | None = None
        self._unsub_bluetooth: CALLBACK_TYPE | None = None
        self._stopped = False
        self._new_device_listeners: set[Callable[[MeshDevice], None]] = set()
        self._connection_listeners: set[Callable[[], None]] = set()
        # address -> (rssi, adv fields) of nodes we could connect to
        self._candidates: dict[str, tuple[int, dict]] = {}

    # ------------------------------------------------------------------ lifecycle

    async def async_start(self) -> None:
        """Start tracking advertisements and connect in the background."""
        for info in bluetooth.async_discovered_service_info(self.hass, connectable=True):
            self._handle_advertisement(info)
        self._unsub_bluetooth = bluetooth.async_register_callback(
            self.hass,
            self._bluetooth_callback,
            bluetooth.BluetoothCallbackMatcher(manufacturer_id=TELINK_MANUFACTURER_ID, connectable=True),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
        self._schedule_reconnect(0)

    async def async_stop(self) -> None:
        self._stopped = True
        if self._unsub_bluetooth:
            self._unsub_bluetooth()
            self._unsub_bluetooth = None
        if self._reconnect_unsub:
            self._reconnect_unsub()
            self._reconnect_unsub = None
        if self._connect_task and not self._connect_task.done():
            self._connect_task.cancel()
            try:
                await self._connect_task
            except (asyncio.CancelledError, HomeAssistantError):
                pass
        self._connect_task = None
        client, self._client = self._client, None
        if client:
            try:
                await client.disconnect()
            except BleakError:
                pass
        self._set_connected(False)

    def add_new_device_listener(self, cb: Callable[[MeshDevice], None]) -> CALLBACK_TYPE:
        self._new_device_listeners.add(cb)
        return lambda: self._new_device_listeners.discard(cb)

    def add_connection_listener(self, cb: Callable[[], None]) -> CALLBACK_TYPE:
        self._connection_listeners.add(cb)
        return lambda: self._connection_listeners.discard(cb)

    def get_or_create_device(self, mesh_address: int) -> MeshDevice:
        device = self.devices.get(mesh_address)
        if device is None:
            device = self.devices[mesh_address] = MeshDevice(mesh_address)
            for cb in list(self._new_device_listeners):
                cb(device)
        return device

    def device_available(self, device: MeshDevice) -> bool:
        return self.connected and time.monotonic() - device.last_seen < DEVICE_TIMEOUT

    # ------------------------------------------------------------------ advertisements

    @callback
    def _bluetooth_callback(self, info: bluetooth.BluetoothServiceInfoBleak, change: bluetooth.BluetoothChange) -> None:
        self._handle_advertisement(info)

    @callback
    def _handle_advertisement(self, info: bluetooth.BluetoothServiceInfoBleak) -> None:
        adv = parse_service_info(info)
        if adv is None or info.name != self.mesh_name:
            return
        self._candidates[info.address] = (info.rssi, adv)
        device = self.get_or_create_device(adv["mesh_address"])
        device.mac_low4 = adv["mac_low4"]
        device.product_uuid = adv["product_uuid"]
        device.rssi = info.rssi
        if len(info.address.replace(":", "")) == 12 and "-" not in info.address:
            device.mac = info.address.upper()
        device.touch()
        device.notify()

    # ------------------------------------------------------------------ connection

    def _set_connected(self, value: bool) -> None:
        if self.connected == value:
            return
        self.connected = value
        for cb in list(self._connection_listeners):
            cb()
        for device in self.devices.values():
            device.notify()

    def _schedule_reconnect(self, delay: float) -> None:
        if self._stopped or self._reconnect_unsub:
            return

        async def _run() -> None:
            try:
                await self.async_ensure_connected()
            except HomeAssistantError as err:
                _LOGGER.debug("Mesh %s: connect failed: %s", self.mesh_name, err)
                self._schedule_reconnect(self._reconnect_delay)
                self._reconnect_delay = min(self._reconnect_delay * 2, RECONNECT_MAX)

        @callback
        def _start(_now: Any) -> None:
            self._reconnect_unsub = None
            if self._stopped:
                return
            self._connect_task = self.hass.async_create_background_task(
                _run(), f"limente mesh {self.mesh_name} connect", eager_start=True
            )

        self._reconnect_unsub = async_call_later(self.hass, delay, _start)

    def _pick_candidates(self) -> list[tuple[BLEDevice, dict]]:
        result = []
        for address, (rssi, adv) in sorted(self._candidates.items(), key=lambda kv: kv[1][0], reverse=True):
            ble_device = bluetooth.async_ble_device_from_address(self.hass, address, connectable=True)
            if ble_device is not None:
                result.append((ble_device, adv))
        return result

    async def async_ensure_connected(self) -> None:
        """Connect and log in if we are not connected. Raises HomeAssistantError."""
        if self._stopped:
            raise HomeAssistantError("mesh is shutting down")
        async with self._connect_lock:
            if self._client and self._client.is_connected and self._session_key:
                return
            candidates = self._pick_candidates()
            if not candidates:
                raise HomeAssistantError(f"no node of mesh {self.mesh_name} in Bluetooth range")
            last_error: Exception | None = None
            for ble_device, adv in candidates[:3]:
                try:
                    await asyncio.wait_for(self._connect_to(ble_device, adv), CONNECT_TIMEOUT)
                    self._reconnect_delay = RECONNECT_MIN
                    return
                except LoginFailed:
                    raise
                except (BleakError, TimeoutError, asyncio.TimeoutError, OSError) as err:
                    last_error = err
                    _LOGGER.debug("Mesh %s: %s failed: %s", self.mesh_name, ble_device.address, err)
            raise HomeAssistantError(f"could not connect to mesh {self.mesh_name}: {last_error}")

    async def _connect_to(self, ble_device: BLEDevice, adv: dict) -> None:
        _LOGGER.debug("Mesh %s: connecting to %s", self.mesh_name, ble_device.address)
        client = await establish_connection(
            BleakClientWithServiceCache,
            ble_device,
            f"limente-{ble_device.address}",
            disconnected_callback=self._on_disconnect,
            max_attempts=2,
        )
        try:
            session_key = await async_login(client, self.mesh_name, self.mesh_password)
            nonce_mac = nonce_mac_for(ble_device, adv)
            self._client, self._session_key, self._nonce_mac = client, session_key, nonce_mac
            self._connected_address = ble_device.address
            await client.write_gatt_char(tl.STATUS_UUID, b"\x01", response=True)
            await client.start_notify(tl.STATUS_UUID, self._on_notify)
        except BaseException:
            self._client = self._session_key = self._nonce_mac = None
            await client.disconnect()
            raise
        connected_node = self.get_or_create_device(adv["mesh_address"])
        connected_node.touch()
        self._set_connected(True)
        _LOGGER.info("Mesh %s: connected via %s", self.mesh_name, ble_device.address)
        # Ask every node to report; DC reports also arrive on their own.
        try:
            await self._write_command(tl.ADDR_BROADCAST, tl.OP_STATUS_QUERY, b"\x10")
        except HomeAssistantError:
            pass

    @callback
    def _on_disconnect(self, client: BleakClientWithServiceCache) -> None:
        if client is not self._client:
            return
        _LOGGER.info("Mesh %s: disconnected from %s", self.mesh_name, self._connected_address)
        self._client = self._session_key = self._nonce_mac = None
        self._set_connected(False)
        self._schedule_reconnect(RECONNECT_MIN)

    # ------------------------------------------------------------------ traffic

    def _on_notify(self, _characteristic: Any, data: bytearray) -> None:
        if not self._session_key or not self._nonce_mac:
            return
        plain = tl.decrypt_notification(self._session_key, self._nonce_mac, bytes(data))
        if plain is None:
            _LOGGER.debug("Mesh %s: notification with bad MIC: %s", self.mesh_name, bytes(data).hex())
            return
        note = tl.parse_notification(plain)
        opcode, params = note["opcode"], note["params"]
        if opcode == tl.OP_ONLINE_STATUS:
            for entry in tl.parse_online_status(params):
                device = self.get_or_create_device(entry["mesh_address"])
                device.online = entry["online"]
                device.is_on = entry["on"]
                device.brightness = entry["brightness"]
                if entry["brightness"]:
                    device.last_brightness = entry["brightness"]
                device.touch()
                device.notify()
        elif opcode == tl.OP_USER_ALL_NOTIFY and (info := tl.parse_device_info(params)):
            device = self.get_or_create_device(note["src"])
            device.mac = info["mac"]
            device.product_uuid = info["product_uuid"]
            device.touch()
            device.notify()
        else:
            _LOGGER.debug("Mesh %s: notification src=%04x op=%02x params=%s",
                          self.mesh_name, note["src"], opcode, params.hex())

    def _next_seq(self) -> bytes:
        self._seq = (self._seq + 1) & 0xFFFFFF
        return self._seq.to_bytes(3, "little")

    async def async_send(self, dest: int, opcode: int, params: bytes) -> None:
        """Encrypt and write one command, connecting first if needed."""
        await self.async_ensure_connected()
        await self._write_command(dest, opcode, params)

    async def _write_command(self, dest: int, opcode: int, params: bytes) -> None:
        async with self._send_lock:
            client, key, mac = self._client, self._session_key, self._nonce_mac
            if client is None or key is None or mac is None:
                raise HomeAssistantError("mesh connection lost")
            wait = COMMAND_SPACING - (time.monotonic() - self._last_send)
            if wait > 0:
                await asyncio.sleep(wait)
            packet = tl.make_command_packet(key, mac, dest, opcode, params, seq=self._next_seq())
            try:
                await client.write_gatt_char(tl.COMMAND_UUID, packet, response=False)
            except BleakError as err:
                raise HomeAssistantError(f"mesh write failed: {err}") from err
            self._last_send = time.monotonic()

    async def async_set_power(self, mesh_address: int, on: bool) -> None:
        await self.async_send(mesh_address, tl.OP_ON_OFF, b"\x01\x00\x00" if on else b"\x00\x00\x00")
        device = self.get_or_create_device(mesh_address)
        device.is_on = on
        device.brightness = device.last_brightness if on else 0
        device.notify()

    async def async_set_brightness(self, mesh_address: int, level: int) -> None:
        """Set brightness 1..100. Turns the node on first if it is off."""
        level = max(1, min(100, int(level)))
        device = self.get_or_create_device(mesh_address)
        if not device.is_on:
            await self.async_send(mesh_address, tl.OP_ON_OFF, b"\x01\x00\x00")
        await self.async_send(mesh_address, tl.OP_BRIGHTNESS, bytes([level]))
        device.is_on = True
        device.brightness = device.last_brightness = level
        device.notify()

    async def async_query_device_info(self, mesh_address: int) -> None:
        await self.async_send(mesh_address, tl.OP_USER_ALL, b"\x10\x76")
