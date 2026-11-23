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
- After a failure the hub looks up `roostfiles.s3.amazonaws.com` (purpose unknown, likely firmware).

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
| `bfw` `wfw` `sfw` `cfw` `cv` `hw` | Firmware: hub, Wi-Fi, sub-GHz radio, LTE modem, config ver., hardware |

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
| `as` | Fixed per sensor type, does not follow arming — keypad/leak 7, doors 6, motion 4 (zone class?) **(?)** |
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

**Wi-Fi provisioning** is done during app setup (soft-AP at `http://192.168.1.1:81` seen in
the app bundle). This is the only path to change Wi-Fi and is still un-reversed — defer.

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
