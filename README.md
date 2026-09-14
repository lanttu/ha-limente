# Limente SMART Bluetooth mesh for Home Assistant

Local control of Limente SMART dimmers (CLASSIC, LUXUS and GREENLINE series, models
520/540/560/580) over Bluetooth, without the Limente app or any cloud.

The dimmers are Sunricher SR-BUS hardware running the Telink BLE mesh firmware, and the
Limente app is Sunricher's EasyThings app. Other EasyThings based products that advertise
their mesh name and use the same Telink protocol are likely to work too; the mesh name and
password are configurable.

## Features

* One light entity per dimmer with on/off and brightness.
* Automatic Bluetooth discovery of the mesh, one config entry per mesh network.
* A single connection into the mesh; the other dimmers are reached through mesh relay,
  exactly like the app does. Reconnects automatically.
* State updates pushed by the dimmers, so changes made with wall switches or the app
  show up in Home Assistant.
* No extra Python requirements; works with a local Bluetooth adapter or an ESPHome
  Bluetooth proxy.

## Installation

HACS: add this repository as a custom repository of type *Integration*, install
"Limente SMART Bluetooth mesh", restart Home Assistant.

Manual: copy `custom_components/limente` into your `config/custom_components/` and restart.

Home Assistant then discovers the dimmers and offers the integration under
Settings > Devices & services. Accept the defaults unless you created your own network in
the Limente app; in that case enter the network name and password shown in the app.
Dimmers that were never set up with the app are on Telink's factory network
`telink_mesh1` / `123`.

## Limitations

* A Telink node accepts one Bluetooth connection at a time. Home Assistant holds a
  connection to one dimmer, so the phone app must connect through another dimmer.
  With a single dimmer, close the app when you want Home Assistant to control it.
* Only brightness is exposed. The protocol also carries RGB and colour temperature
  (opcode `E2`); open an issue with your model if you have such a device.
* Bluetooth range applies to whichever dimmer Home Assistant connects to.

## Protocol

Everything learned while reverse engineering is in [docs/PROTOCOL.md](docs/PROTOCOL.md).
The `tools/` directory contains a scanner, a command-line probe and a decryptor for
Bluetooth captures, useful for adding other devices:

    uv sync
    uv run python tools/scan.py 12
    uv run python tools/probe.py --address AA:BB:CC:DD:EE:FF on
    uv run python tools/probe.py --address AA:BB:CC:DD:EE:FF --dest 00ac dim 40
    uv run python tools/decrypt_snoop.py capture.pklg --mac AA:BB:CC:DD:EE:FF --cred Srm@7478@a:475869

On macOS run these from a normal Terminal window; sandboxed processes are refused
Bluetooth access.

## Development

    uv sync --all-groups
    uv run pytest

The tests replay packets from a real capture of the Limente app, so the crypto is checked
against the real thing without hardware.

## Contributing

I wrote this integration for my own home, so it covers the devices I have and the features
I use. Contributions are welcome all the same: bug reports, support for other EasyThings
based products, and pull requests. Please include a Bluetooth capture or the output of
`tools/probe.py` when reporting a device that does not work; see the [Protocol](#protocol)
section for how to get one.

## Disclaimer

Not affiliated with Oy Limente Ab, Sunricher or Telink. Do not write to the OTA
characteristic, and do not send the kick-out opcode (`E3`) unless you mean to factory reset
a dimmer.
