"""Light entities, one per mesh dimmer."""
from __future__ import annotations

from typing import Any

from homeassistant.components.light import ATTR_BRIGHTNESS, ColorMode, LightEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import LimenteConfigEntry
from .const import DOMAIN
from .mesh import LimenteMesh, MeshDevice


def _unique_id(entry: LimenteConfigEntry, mesh_address: int) -> str:
    return f"{entry.entry_id}_{mesh_address:04x}"


async def async_setup_entry(
    hass: HomeAssistant, entry: LimenteConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    mesh = entry.runtime_data
    known: set[int] = set()

    # Re-create entities seen in earlier runs so they exist before the mesh reports them.
    registry = er.async_get(hass)
    for reg_entry in er.async_entries_for_config_entry(registry, entry.entry_id):
        prefix = f"{entry.entry_id}_"
        if reg_entry.domain == "light" and reg_entry.unique_id.startswith(prefix):
            try:
                mesh.get_or_create_device(int(reg_entry.unique_id[len(prefix):], 16))
            except ValueError:
                continue

    @callback
    def _add(device: MeshDevice) -> None:
        if device.mesh_address in known:
            return
        known.add(device.mesh_address)
        async_add_entities([LimenteLight(entry, mesh, device)])

    for device in list(mesh.devices.values()):
        _add(device)
    entry.async_on_unload(mesh.add_new_device_listener(_add))


class LimenteLight(LightEntity):
    _attr_has_entity_name = True
    _attr_name = None
    _attr_should_poll = False
    _attr_color_mode = ColorMode.BRIGHTNESS
    _attr_supported_color_modes = {ColorMode.BRIGHTNESS}

    def __init__(self, entry: LimenteConfigEntry, mesh: LimenteMesh, device: MeshDevice) -> None:
        self._mesh = mesh
        self._device = device
        self._attr_unique_id = _unique_id(entry, device.mesh_address)

    @property
    def device_info(self) -> DeviceInfo:
        info = DeviceInfo(
            identifiers={(DOMAIN, self._attr_unique_id)},
            name=self._device.name,
            manufacturer="Limente (Sunricher)",
            model="SMART Bluetooth mesh dimmer",
        )
        if self._device.mac:
            info["connections"] = {(dr.CONNECTION_BLUETOOTH, self._device.mac)}
        if self._device.product_uuid is not None:
            info["model_id"] = f"0x{self._device.product_uuid:04X}"
        return info

    @property
    def available(self) -> bool:
        return self._mesh.device_available(self._device)

    @property
    def is_on(self) -> bool:
        return self._device.is_on

    @property
    def brightness(self) -> int | None:
        level = self._device.brightness if self._device.is_on else self._device.last_brightness
        return round(level * 255 / 100) if level else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"mesh_address": self._device.mesh_address, "rssi": self._device.rssi}

    async def async_added_to_hass(self) -> None:
        self._device.listeners.add(self.async_write_ha_state)
        self.async_on_remove(self._mesh.add_connection_listener(self.async_write_ha_state))
        if self._device.mac is None and self._mesh.connected:
            try:
                await self._mesh.async_query_device_info(self._device.mesh_address)
            except Exception:  # noqa: BLE001 - best effort, the mesh may be busy
                pass

    async def async_will_remove_from_hass(self) -> None:
        self._device.listeners.discard(self.async_write_ha_state)

    async def async_turn_on(self, **kwargs: Any) -> None:
        if ATTR_BRIGHTNESS in kwargs:
            await self._mesh.async_set_brightness(self._device.mesh_address, round(kwargs[ATTR_BRIGHTNESS] * 100 / 255))
        else:
            await self._mesh.async_set_power(self._device.mesh_address, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._mesh.async_set_power(self._device.mesh_address, False)
