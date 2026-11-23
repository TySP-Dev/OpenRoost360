# Roost Security360 SmartBase — local protocol notes

Reverse-engineered from a SmartBase (firmware `xb.5.0.1`) talking to a local stand-in server.
Items marked **(?)** are inferred from one test run and still need confirming.

## Boot / connection flow

1. DNS `us-central1-roostprod.cloudfunctions.net` → HTTPS `POST /getCurrentTime` (empty body).
   Must answer `{"time": <epoch ms>}` or the hub says "failed to connect" and gives up.
2. DNS `us-central1-mqtt.clearblade.com` → MQTT 3.1.1 over TLS on **port 443**.
   - Hub does **not** validate the server certificate (self-signed works).
   - Client ID: `projects/roostprod/locations/us-central1/registries/baseregistry/devices/z<hub-mac-no-colons>`
   - Username `unused`, password = ES256 JWT (`aud: roostprod`, 24 h expiry). Can be ignored.
3. Hub publishes a status message (`ev: "2"`) to `/devices/<id>/events`.
4. Hub subscribes to `/devices/<id>/config` and `/devices/<id>/commands/#`.
   Server must publish to `/config` (an **empty payload** works) or the hub gives up after ~3 min.
5. Keepalive PINGREQ every 60 s.
- If the server goes away (restart), the hub reconnects on its own within ~1 min.
- First TLS attempt each time is dropped by the hub and retried immediately; harmless.
- After a failure (e.g. a bad `getCurrentTime` reply) the hub fetches `GET /acert.bin` from
  `roostfiles.s3.amazonaws.com` — its cert/endpoint bundle, see below. That is the **only**
  request in the recovery path: even when served the genuine file over a keep-alive
  connection, it makes no follow-up request and no other DNS lookups, then goes back to
  retrying `getCurrentTime` every 60 s. Once the time reply is good again it connects to
  MQTT on its own — no reboot needed.

**Power behaviour:** on mains (`pw: 1`) the hub stays connected and publishes every event live.
On battery (`pw: 0`) it connects, gets config, and disconnects — events are not sent live.

## Hub message (`/devices/<id>/events`, QoS 1, JSON)

| Key | Meaning |
|---|---|
| `ev` | Hub event: `0` arm-state change, `1` sensor event (see `dj`), `2` boot/check-in, `4` **alarm** |
| `as` | Hub arm state: `0` disarmed, `2` armed Home (reported immediately, no second message), `8` arming Away (exit delay, ~60 s), `4` armed Away. Not the same as `dj.as` |
| `da` | Disarm source, present on disarm: `"ow"` owner PIN, `"ho"` **hostage (duress) PIN** — the hub disarms normally, so this field is the only sign of duress. Guest PIN value not yet seen (likely `"gu"`?) |
| `pw` | `1` on mains power, `0` on battery |
| `bat` | Hub backup battery, mV |
| `fr` | **Fire alarm active** — `1` while the smoke listener hears an alarm, back to `0` when it stops. Sent as `ev: "0"` with no `dj` object |
| `mo`, `la` | Flags, always 0 so far (stayed 0 during motion and leak tests) **(?)** |
| `t` | Epoch seconds |
| `co` | Connection: `w` = Wi-Fi |
| `ss`, `bs`, `wc`, `rs` | Wi-Fi SSID, BSSID, channel, RSSI |
| `cl` | `[[t, temp °C, humidity %]]` — hub's own climate reading |
| `cs` | Cellular signal; `99` = none |
| `icc` | SIM ICCID (redact when sharing) |
| `log` | Hub diary `[t, code]`: `8` online, `10` connect attempt failed/retrying, `19` connection lost **(?)**, `25` boot **(?)** |
| `bfw` `wfw` `sfw` `cfw` `hw` | Firmware: hub, Wi-Fi, sub-GHz radio, LTE modem; hardware |
| `cv` | Version of the installed **cert/endpoint bundle** (`acert.bin`, see below) — *not* a config-schema version |

## Cert/endpoint bundle (`acert.bin`)

Fetched from `roostfiles.s3.amazonaws.com/acert.bin` in the recovery path. A tiny archive
(all integers big-endian; CRCs are standard CRC-32, all verified):

```
0x000  version string, 16 bytes, NUL-padded   ("0.0.7" — matches the hub's cv field)
0x010  u32 file count (3)
0x014  u32 unknown (7)
0x018  file table, 24 bytes per entry: u32 size, u32 CRC-32, name[16] NUL-padded
0x400  file data, concatenated in table order
```

| File | Contents |
|---|---|
| `wcert.bin` | 4096-byte binary blob, magic `11f1 12f2 … 18f8`, 0xFF-padded — likely the Wi-Fi module's CA store |
| `ccert.bin` | Root CAs as length-prefixed PEMs: Amazon Root CA 1, GlobalSign ECC R4, Google Trust Services LTSR/R1–R4 (likely for the LTE modem) |
| `url.txt` | MQTT broker hostname: `us-central1-mqtt.clearblade.com` |

So the bundle **sets the hub's MQTT host**. A second bundle in the bucket, `bcert.bin`
(version `1.1.1`, Jul 2024), has the same layout and the same `wcert.bin` but
`url.txt` = `iotcore.getroost.com` — Roost's post-ClearBlade broker. Hubs reporting
`cv: 0.0.7` never moved over. Serving our own bundle (with `url.txt` pointing at a local
name) could remove the need for DNS/iptables redirection, but it's an untested write to the
hub — don't try it without a recovery plan.

## The `roostfiles` S3 bucket

ListBucket is denied (403); GETs are public. With listing denied, S3 returns 403 for missing
keys too, so only a 200 is meaningful. Known objects:

| Key | Size | Notes |
|---|---|---|
| `acert.bin` | 15953 | Bundle v0.0.7 (above) |
| `bcert.bin` | 17284 | Bundle v1.1.1, `iotcore.getroost.com` |
| `xs.4.3.0.bin`, `xs.4.4.0.bin`, `xs.4.5.0.bin` | 122880 each | **Sensor** firmware (keypad/door/motion/leak `fw` versions). Plain ARM Thumb, TI-RTOS strings (TI SimpleLink sub-GHz MCU). 4.3.0→4.4.0 differs only in version/CRC bytes. Almost no strings; nothing about `/config` (sensors never see it) |

Not found (403) — hub firmware under any obvious name: `xb.5.0.1.bin` and neighbouring
versions, `xe.4.4.0.bin`, and the hub's `sfw`/`wfw`/`cfw`/`hw` strings as keys. Since the
recovery path only ever pulls `acert.bin`, hub firmware updates must be cloud-triggered
(e.g. a `/commands` message with a URL), not discovered by the hub.

## Sensor sub-object (`dj`)

| Key | Meaning |
|---|---|
| `id` | Sensor slot ID — assigned per hub at pairing, so it differs between installs |
| `dt` | Device type (stable per model — see table below) |
| `ev` | Sensor event code (per type, below) |
| `mac` | Sensor radio address |
| `bat` | Battery, raw units (keypad ≈ 2940, others 680–1010) **(?)** |
| `rs` | RSSI at hub |
| `fw`, `hw` | Sensor firmware / hardware |
| `as` | Per-sensor **alert mode** — the arm states in which this sensor triggers, as a bitmask matching hub `as` values: `1` always/24-h, `2` Home, `4` Away. Defaults seen: keypad/leak 7 (always), doors 6 (Home+Away), motion 4 (Away only). Set from the app per sensor via `setupSensorAlertMode {id, alertSetup}` **(?)** — bit meanings inferred from the defaults, not yet confirmed by a change |
| `pi` | Counter / retry index **(?)** |
| `cl` | Leak sensors: `[[t, temp °C, humidity %]]` |
| `log` | `[t, code]`; `233` appears on door open, `16`, `1`, `2` seen on others |
| `tok` | Always `"abcdefgh"` |

### Device types seen

| `dt` | Device | `fw` | Event codes |
|---|---|---|---|
| 2883353816 | Keypad | xs.4.5.0 | `0` arm/disarm input, `12` **panic** (X + OK held) |
| 588387123 | Entry (door) sensor | xs.4.4.0 | `14` open, `15` closed |
| 2455340117 | Motion sensor | xs.4.5.0 | `17` motion, `18` clear, `0` check-in. Reports while disarmed. `18` is a timer (~100 s after detection), not "room empty"; new motion isn't reported until after it |
| 287458440 | Water leak / temp sensor | xs.4.4.0 | `1` wet, `0` dry |
| 1149772305 | Smoke alarm listener **(?)** | xe.4.4.0 | `0` check-in. Sends **no** `dj` event on alarm — the only signal is the hub flag `fr` |

## Example fire alarm (system disarmed)

```
+0:00  ev 0  as 0  fr 1   smoke listener hears alarm
+0:15  ev 0  as 0  fr 0   alarm stopped
```
Fire is reported regardless of arm state.

## Example panic (keypad X + OK)

```
+0:00  ev 1  as 0   keypad dj.ev 12   PANIC
+0:05  ev 1  as 0   keypad dj.ev 0
```
Panic is reported from any arm state and does not change `as`.

## Example duress disarm (hostage PIN)

```
+0:00  ev 0  as 0  da "ho"   disarmed with hostage PIN — looks like a normal disarm at the keypad
```

## Example alarm sequence (armed Away)

```
+0:00  ev 0  as 8   keypad → arming Away, exit delay
+1:00  ev 0  as 4   armed Away
+1:52  ev 1         entry sensor ev 14 (open)
+2:37  ev 4  as 4   ALARM (~45 s entry delay expired)
+3:10  ev 0  as 0   da "ow" — disarmed from keypad
```

## Settings & pairing (from official user manual)

**Settings that were app-only** (manual, "Connecting to Wi-Fi" > Key Features Enabled with Wi-Fi):
set PIN codes, change entry/exit delay, enable/disable entry chime, remote arm/disarm,
full system test, activate monitoring. All of these went app -> Roost cloud -> hub on the
`/config` topic. There is **no keypad sequence** to change a PIN.

Implication: remote PIN/delay/chime setting requires reproducing the cloud's `/config`
document format. Confirmed the hub *does* take settings via `/config` (that is how the
current PINs got there), but the exact schema is still unknown. Attempts with bare JSON
(`{"gu":"1357"}`, `{"cv":"0.0.9"}`) were PUBACK'd but did **not** take effect — the hub
likely expects a complete/validated config doc, not a partial one. `cv` is probably a
read-only firmware config-schema version (always reports `0.0.7`). Field names seen in the
app bundle: `pin`, `entryDelay`, `exitDelay`, `guest`/`hostage` PINs, `DoorChime` — but the
app->cloud names are not guaranteed identical to cloud->hub names.

**Pairing is LOCAL — no cloud needed.** Gray button on the back of the SmartBase puts it in
pairing mode (light ring blinks green) for 10 minutes. Any sensor auto-joins when its red
tab is pulled (or re-pulled) while the hub is pairing; the hub gives an audible confirm and
then reports that sensor in normal `dj` events. So the webapp's "add/re-pair sensor" flow is
just: tell the user to hold the gray button, then watch for a `dj` with an `id` we have not
seen before and surface it for naming. This needs nothing we have not already decoded.

**Wi-Fi provisioning** is a direct-to-hub soft-AP API — fully decoded, see
"Wi-Fi provisioning (soft-AP)" below.

## PIN model (from app bundle, Roost 360 v2.5.17)

The app manages PINs through cloud REST actions: `CREATE_PIN` / `UPDATE_PIN` / `DELETE_PIN`
plus an "access list" (`GET_ACCESS_LIST` / `UPDATE_ACCESS_LIST`). A PIN entry's vocabulary
in the app: fields `code`, `type`, `name`/`label`, `digits`, `active`/`enabled`, `id`;
types `owner`, `guest`, `hostage` (4-digit). The hub's own events use terse 2-letter codes
for the same types — `ow` (owner), `ho` (hostage), and by inference `gu` (guest) — in the
`da` disarm-source field.

Other confirmed settings vocab: `entryDelay`, `exitDelay`, `DoorChime`/`door_chime`,
`armState`, `ARM_SYSTEM`. Wi-Fi provisioning is a direct-to-hub soft-AP (`janusSoftAP`,
`softAPSSID`, `http://192.168.1.1:81`), separate from the cloud path.

**The wall:** the app talks to Roost's cloud (app->cloud schema above); the cloud transforms
that and pushes the result to the hub on `/config` (cloud->hub schema — UNKNOWN). The
`owner`->`ow` style remap proves a server-side transform sits between the two, and that
transform lives in Roost's cloud functions, which are not in the APK. So the exact `/config`
document the hub accepts is not derivable from the app. It can only come from the hub
firmware (flash read) or continued black-box experiments on `/config` using this vocabulary.

**What the webapp CAN do for PINs today:** report disarm-by-type (owner/guest/hostage via
`da`) and silently alert on hostage. Reading or writing PIN values is blocked on the schema.

## Cloud→hub black-box tests — all negative (2026-11-22)

The hub PUBACKs **everything** on `/config` and `/commands` (so a PUBACK means nothing) and
reacted to none of these — no arm change, no published event at all:

| Channel | Payloads |
|---|---|
| `/config` | empty; `{"gu":"…"}`; `{"cv":"0.0.9"}`; `{"pins":[{type,code,name}]}`; flat `{"ow","ho","ex":30}` (exit delay measured unchanged at 60 s) |
| `/commands` (base) | `{"as":2}`, `{"as":"2"}`, `{"cmd":"arm","as":2}`, `{"cmd":"arm","mode":2}`, `{"armedMode":"home"}`, `{"cmd":"armSystem","armedMode":"home"}` |
| `/commands/<sub>` for `arm`, `armSystem`, `settings`, `config`, `cmd`, `command`, `action`, `state`, `set` | each of `{"as":2}`, `{"armedMode":"home"}`, `{"cmd":"arm","as":2}`, bare `2` |

So it isn't just the field names: either the hub expects a framing/encoding we haven't
guessed (binary, signed, wrapped, versioned), or a subtopic name outside this list. Don't
repeat these; the firmware dump is the efficient next step. The listener can target subtopics
with a first line `@<sub>` in `command.payload`.

## Wi-Fi provisioning (soft-AP) — from app bundle v2.5.17

Hub-native; no cloud involved. Decompiled from the Hermes bundle (`hermes-dec`); `scan`
**confirmed live 2026-11-22** (`provision` not yet exercised).

1. **Enter soft-AP mode:** press the grey button on the bottom of the SmartBase until the light
   ring **blinks purple** (blinking green is sensor-pairing mode — same button).
2. The hub broadcasts an **open** network `Roost-Base-XXXX`, where `XXXX` = last two bytes of the
   hub MAC, uppercase, no colon (app joins it with `connectToSSID`, no password).
3. All calls: `POST http://192.168.1.1:81`, `Content-Type: application/json`.

**Scan**
```json
{"cmd": "scan", "cc": "<country>", "sct": "0"}
```
Response (live): `{"result":"success","scanList":[[ssid, rssi, sec], ...],"log":"[0]","enc":"0"}`
— `sec` is a small integer (`2` for every WPA2 network seen), not a raw WICED enum. The app
sorts by rssi and drops empty (hidden) SSIDs. The HTTP server takes one connection at a time;
a request fired immediately after the previous one is refused — wait a second and retry.

**Behaviour seen live:** entering purple mode makes the hub drop MQTT (clean DISCONNECT). The
AP comes up on channel 6 and serves DHCP (client got `192.168.1.100`). About 45 s after
the scan the hub went back to its saved Wi-Fi and MQTT **while still broadcasting the AP**
(AP and station at the same time). A hub reboot cleared the AP. An open setup AP lets anyone
in range re-provision the hub, so always reboot afterwards.

**Provision**
```json
{"cmd": "provision", "cc": "<country>", "ssid": "<ssid>", "pwd": "<password>",
 "sec": "<sec from scanList entry, as string>", "enc": "0"}
```
`sec` is opaque — echo back the value the scan returned for that network (likely a Cypress
WICED `wiced_security_t` value). The app also uses `scan` with `cc: "0x00005355"` as a
"am I connected to the hub AP?" probe.

`cc` is a **Cypress WICED country code** (`'X' | 'Y'<<8`), sent as a decimal string:
`21333` = `0x5355` "US" (used for US, Canada, Brazil), `16967` = `0x4247` (EU countries,
Australia, China). This also identifies the hub's Wi-Fi module as WICED-based (`wfw`).

## App → cloud API — from app bundle v2.5.17

Cloud Functions at `https://us-central1-roostprod.cloudfunctions.net`, all `POST` JSON with a
session `Authorization` header. This is the half Roost's servers translated into `/config`
and `/commands` for the hub; documented here as the vocabulary to target.

| Call | Body | Notes |
|---|---|---|
| `armSystem` | `{id, armedMode}` | `armedMode`: `"off"` / `"home"` / `"away"` (hub reports `as` 0/2/4); app also tracks `exitDelay` |
| `createPin` / `updatePin` | `{id, owner: "1234"}` · `{id, hostage: "1234"}` · `{id, guest: {name, pin}}` | One owner, one hostage, named guests; 4 digits |
| `deletePin` | `{id, …}` | |
| `getAccessList` | `{id}` | Returns list of `{id, name, …}` entries (Owner / Hostage / Guest) |
| `setupSensorAlertMode` | `{id: <sensor>, alertSetup}` | Per-sensor alert mode — almost certainly the hub's `dj.as` |
| `/updateDevice` | `{id, location, name, group, imageUploaded, tempUnitsFahrenheit, tempAlert, tl, th, humAlert, hl, hh, dc, en, ex}` | `dc` door chime (`1` = on), `en` entry delay, `ex` exit delay, `tl`/`th` temp low/high, `hl`/`hh` humidity low/high |
| `/getDevice`, `/deleteDevice`, `/getHistory {sensor, count}` | | |
| `associateBase` | `{address, qrCode}` | Claims a hub to an account |
| `getConfig` | — | **App** config (feature flags, branding, location/name lists) — *not* hub config |

**Key observation:** the cloud's device documents use the **same terse keys as the hub**
(`dc`, `en`, `ex`, `as`, `tl`/`th`, `hl`/`hh` are read straight off device objects in the app),
so the cloud→hub transform may be thinner than assumed — plausibly `/config` carries
per-device objects with these keys. Untested; any `/config` experiment must still include the
owner PIN and be followed by a keypad disarm check.

No firmware-update/OTA call exists in the app (it only *displays* `firmwareRevision`), so hub
firmware updates were entirely cloud-driven.
