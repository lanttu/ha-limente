"""Constants for the Limente SMART integration."""
from __future__ import annotations

DOMAIN = "limente"

CONF_MESH_NAME = "mesh_name"
CONF_MESH_PASSWORD = "mesh_password"

# Telink company id in advertisements (decimal, as HA's bluetooth matchers use it).
TELINK_MANUFACTURER_ID = 0x0211

# Seconds between command writes; the app spaces its packets about 300 ms apart.
COMMAND_SPACING = 0.2
# Seconds without an advertisement or status report before a dimmer is unavailable.
DEVICE_TIMEOUT = 600
# Reconnect backoff bounds.
RECONNECT_MIN = 2
RECONNECT_MAX = 60
CONNECT_TIMEOUT = 30
