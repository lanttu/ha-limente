"""Config flow: discover a mesh node over Bluetooth and check the credentials."""
from __future__ import annotations

import logging
from typing import Any

from bleak import BleakError
import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.core import HomeAssistant

from . import telink as tl
from .const import CONF_MESH_NAME, CONF_MESH_PASSWORD, DOMAIN
from .mesh import LoginFailed, async_validate_login, parse_service_info

_LOGGER = logging.getLogger(__name__)


def _discovered_meshes(hass: HomeAssistant) -> dict[str, list[bluetooth.BluetoothServiceInfoBleak]]:
    """Mesh name -> nodes currently advertising, strongest first."""
    meshes: dict[str, list[bluetooth.BluetoothServiceInfoBleak]] = {}
    for info in bluetooth.async_discovered_service_info(hass, connectable=True):
        if parse_service_info(info) and info.name:
            meshes.setdefault(info.name, []).append(info)
    for nodes in meshes.values():
        nodes.sort(key=lambda i: i.rssi, reverse=True)
    return meshes


class LimenteConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._mesh_name: str | None = None

    async def async_step_bluetooth(self, discovery_info: bluetooth.BluetoothServiceInfoBleak) -> ConfigFlowResult:
        if parse_service_info(discovery_info) is None or not discovery_info.name:
            return self.async_abort(reason="not_supported")
        await self.async_set_unique_id(discovery_info.name)
        self._abort_if_unique_id_configured()
        self._mesh_name = discovery_info.name
        self.context["title_placeholders"] = {"name": discovery_info.name}
        return await self.async_step_user()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        meshes = _discovered_meshes(self.hass)
        if user_input is not None:
            mesh_name = user_input[CONF_MESH_NAME].strip()
            await self.async_set_unique_id(mesh_name)
            self._abort_if_unique_id_configured()
            nodes = meshes.get(mesh_name, [])
            if not nodes:
                errors["base"] = "no_devices_found"
            else:
                try:
                    await async_validate_login(self.hass, nodes[0].address, mesh_name, user_input[CONF_MESH_PASSWORD])
                except LoginFailed:
                    errors["base"] = "invalid_auth"
                except (BleakError, TimeoutError) as err:
                    _LOGGER.debug("Validation connect failed: %s", err)
                    errors["base"] = "cannot_connect"
                else:
                    return self.async_create_entry(
                        title=f"Limente mesh {mesh_name}",
                        data={CONF_MESH_NAME: mesh_name, CONF_MESH_PASSWORD: user_input[CONF_MESH_PASSWORD]},
                    )

        default_name = self._mesh_name or next(iter(meshes), tl.DEFAULT_MESH_NAME)
        if not meshes and user_input is None and self._mesh_name is None:
            return self.async_abort(reason="no_devices_found")
        schema = vol.Schema(
            {
                vol.Required(CONF_MESH_NAME, default=default_name): str,
                vol.Required(CONF_MESH_PASSWORD, default=tl.DEFAULT_MESH_PASSWORD): str,
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={"found": ", ".join(sorted(meshes)) or "-"},
        )
