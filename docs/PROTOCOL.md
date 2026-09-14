# Limente SMART BLE protocol

Source: decompiled Limente Android app 2.0.0 (`com.oylimenteab.limente`), which is
Sunricher's EasyThings app (`com.sunricher.easythings`) built on the Telink
SmartLight mesh SDK (`com.telink.bluetooth.light`, `libTelinkCrypto.so`).

## Identity

| Item | Value |
|---|---|
| Advertised name | `SBUS LIGHT` |
| Vendor id | `0x0211` (Telink), little-endian `11 02` in packets |
| Default mesh name | `Srm@7478@a` (`Constants.DEFAULT_NETNAME`) |
| Default mesh password | `475869` (`Constants.DEFAULT_PASSWORD`) |
| Telink factory credentials | `telink_mesh1` / `123` (unprovisioned device) |

The light exposes the *current* mesh name as the Device Information
"Manufacturer Name String". A user who created a custom network in the app has
different credentials; they are stored in the app's local database (`Network`).

## GATT

Service `00010203-0405-0607-0809-0A0B0C0D1910`

| Characteristic | UUID suffix | Use |
|---|---|---|
| Status | `1911` | write `01` to enable, then notifications |
| Command | `1912` | write-without-response, 20-byte encrypted packets |
| OTA | `1913` | firmware update, do not touch |
| Pair | `1914` | login handshake |

## Advertisement

Manufacturer-specific data (the SDK uses the second `0xFF` record):

    vendor(2 LE) meshUUID(2 LE) macLow4(4) productUUID(2 LE) status(1) meshAddress(2 LE)

`macLow4` is the device-order MAC prefix used in every nonce, so the full MAC is
not needed on macOS.

## Login

    K   = pad16(meshName) XOR pad16(password)
    r   = random(8)
    req = 0x0C | r | AES(pad16(r), K)[0:8]          -> write Pair
    rsp = read Pair                                  -> 0x0D | r2(8) | ...   (0x0E = bad credentials)
    session_key = AES(K, r | r2)

All AES is 128-bit ECB on byte-reversed key and block, output reversed
(`com.telink.crypto.AES`).

## Command packet (to Command characteristic)

Plaintext, 20 bytes: `seq(3 LE) | 00 00 | dst(2 LE) | opcode|0xC0 | vendor(2 LE) | params(10)`
Nonce: `macLow4 | 01 | seq(3)`
Encrypted: `seq(3) | MIC(2) | CTR( dst | opcode | vendor | params )`
MIC = first 2 bytes of CBC-MAC with IV `nonce | len(15)`.
CTR keystream block i = AES(session_key, `i | nonce` padded).

`dst` `0x0000` = the connected node, `0xFFFF` = every node, `0x8000+n` = group n
(Telink convention), otherwise the unicast mesh address from the advertisement.

## Notification (from Status characteristic)

    seq(3) | src(2 LE) | MIC(2) | CTR( opcode | vendor(2) | params(10) )

Nonce: `macLow4[0:3] | packet[0:5]`.

## Verified against a live capture (capture2.pklg, iOS app, 2026-09-09)

* Login with `Srm@7478@a` / `475869` matched the app's handshake; the derived session key
  decrypts all traffic with valid MICs.
* Each dimmer is addressed by its unicast mesh address (here `0x00AC` and `0x00E9`, equal
  to the low MAC byte). The phone stays connected to one dimmer and sends `dst=0x00E9`
  to reach the other through the mesh.
* On connect the app sends `EA 10 76` to each device and gets `EB 76 productUUID(2) MAC(6)`
  back (`EB addr 76 productUUID(2) MAC(6)` as raw params), i.e. a device-info query returning the full MAC.
* iOS app on/off params are `01 01 00` / `00 01 00` (second byte likely a fade step);
  the Android code uses `01 00 00`. Both work.
* `DC` reports arrive after every change: `addr sn brightness ff`; `sn` is a rolling
  counter (nonzero = online), brightness 0 when off.

## Opcodes and params used by the app

| Opcode | Meaning | Params |
|---|---|---|
| `D0` | on/off | `01 00 00` on, `00 00 00` off |
| `D2` | brightness | `level` 0..100 |
| `E2` | colour | `04 r g b` RGB; `05 x` colour temperature 0..100 |
| `DA` | status query | `10` (Telink standard, app relies on DC instead) |
| `DB` | status response | |
| `DC` | online status report | repeated `addr status brightness reserve`; status 0 = offline, brightness 0 = off |
| `DD` | group query | `10 01` |
| `EA` | vendor "user all" | `10 76` = get device info, reply `EB` params `addr 76 productUUID(2) MAC(6)` |
| `E4` | set time | `y(2 LE) mon day h m s` |
| `E5`/`E6`/`E7` | timers/alarms | |
| `C0`/`C1` | scenes | |
| `E3` | kick out / factory reset | never send by accident |
| `E0` | set mesh address | |

## Cloud

The app has an optional cloud at `easythings.smartcodecloud.com` (token, devices,
sync_macs). Not needed for local control.
