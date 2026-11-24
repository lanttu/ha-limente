"""Limente SMART Bluetooth mesh dimmers (Sunricher EasyThings / Telink mesh)."""
from __future__ import annotations

import asyncio

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import CONF_MESH_NAME, CONF_MESH_PASSWORD
from .mesh import LimenteMesh

PLATFORMS = [Platform.LIGHT]
DISCOVERY_TIMEOUT = 15

type LimenteConfigEntry = ConfigEntry[LimenteMesh]


async def async_setup_entry(hass: HomeAssistant, entry: LimenteConfigEntry) -> bool:
    mesh = LimenteMesh(hass, entry.data[CONF_MESH_NAME], entry.data[CONF_MESH_PASSWORD])
    first_node = asyncio.Event()
    # Register before startup to catch both cached and newly scanned nodes.
    unsubscribe = mesh.add_new_device_listener(lambda _device: first_node.set())
    discovery_complete = False
    try:
        await mesh.async_start()
        if not mesh.devices:
            async with asyncio.timeout(DISCOVERY_TIMEOUT):
                await first_node.wait()
        discovery_complete = True
    except TimeoutError as err:
        raise ConfigEntryNotReady(
            f"No {entry.data[CONF_MESH_NAME]} mesh node in Bluetooth range"
        ) from err
    finally:
        unsubscribe()
        if not discovery_complete:
            await mesh.async_stop()
    entry.runtime_data = mesh
    entry.async_on_unload(mesh.async_stop)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: LimenteConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
