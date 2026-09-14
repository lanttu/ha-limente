"""Limente SMART Bluetooth mesh dimmers (Sunricher EasyThings / Telink mesh)."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import CONF_MESH_NAME, CONF_MESH_PASSWORD
from .mesh import LimenteMesh

PLATFORMS = [Platform.LIGHT]

type LimenteConfigEntry = ConfigEntry[LimenteMesh]


async def async_setup_entry(hass: HomeAssistant, entry: LimenteConfigEntry) -> bool:
    mesh = LimenteMesh(hass, entry.data[CONF_MESH_NAME], entry.data[CONF_MESH_PASSWORD])
    await mesh.async_start()
    if not mesh.devices:
        await mesh.async_stop()
        raise ConfigEntryNotReady(f"No {entry.data[CONF_MESH_NAME]} mesh node in Bluetooth range")
    entry.runtime_data = mesh
    entry.async_on_unload(mesh.async_stop)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: LimenteConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
