"""Constants for the Limente SMART integration."""
from __future__ import annotations

DOMAIN = "limente"

CONF_MESH_NAME = "mesh_name"
CONF_MESH_PASSWORD = "mesh_password"

# Telink company id in advertisements (decimal, as HA's bluetooth matchers use it).
TELINK_MANUFACTURER_ID = 0x0211

# Seconds between command writes; the app spaces its packets about 300 ms apart.
COMMAND_SPACING = 0.2
# Seconds without an advertisement before a dimmer the mesh has not reported
# on yet is unavailable. Once a DC report covers a node, that report decides.
DEVICE_TIMEOUT = 600
# Seconds between broadcast status queries while connected. Keeps DC reports
# coming for idle nodes and proves the connection still carries writes.
STATUS_INTERVAL = 300
# Reconnect backoff bounds.
RECONNECT_MIN = 2
RECONNECT_MAX = 60
CONNECT_TIMEOUT = 30
