"""Scan for Telink mesh lights and dump/parse their advertisement data.

Run from a normal Terminal window (macOS Bluetooth permission).
The `mac_low4` value printed for each light is what --mac in probe.py needs.
"""
import asyncio
import os
import sys

from bleak import BleakScanner

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from custom_components.limente import telink as tl  # noqa: E402


async def main(seconds: float = 12.0) -> None:
    seen: dict = {}

    def cb(dev, adv):
        name = (adv.local_name or dev.name or "")
        if tl.SERVICE_UUID in adv.service_uuids or tl.VENDOR_ID in adv.manufacturer_data or "SBUS" in name.upper():
            seen[dev.address] = (dev, adv)

    kwargs = {}
    if sys.platform == "darwin":
        kwargs["cb"] = {"use_bdaddr": True}  # best effort; may still yield a UUID
    try:
        scanner = BleakScanner(cb, **kwargs)
        await scanner.start()
    except Exception:
        scanner = BleakScanner(cb)
        await scanner.start()
    await asyncio.sleep(seconds)
    await scanner.stop()

    if not seen:
        print("no Telink mesh devices seen")
        return
    for addr, (dev, adv) in seen.items():
        print(f"\n== {adv.local_name or dev.name}  address={addr}  rssi={adv.rssi}")
        print("  service uuids:", adv.service_uuids)
        for cid, data in adv.manufacturer_data.items():
            print(f"  manufacturer 0x{cid:04x} ({len(data)} B): {data.hex(' ')}")
            parsed = tl.parse_advertisement(data, company_id=cid)
            if parsed:
                print("  parsed telink adv:", parsed)
                print(f"  -> probe.py --address {addr} --mac {parsed['mac_low4']}")
        for uuid, data in adv.service_data.items():
            print(f"  service data {uuid}: {data.hex(' ')}")


asyncio.run(main(float(sys.argv[1]) if len(sys.argv) > 1 else 12.0))
