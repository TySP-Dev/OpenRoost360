# OpenRoost360 API v1 (for the mobile app)

The mobile app talks to the OpenRoost server, and the server talks to the hub, the same shape as Roost's
original app → cloud → hub. Everything the dashboard shows is available here. The full, generated route list
(with roles and planned markers) is at **`GET /api/v1/openapi.json`**.

## Connecting securely

Always use **HTTPS** (default port 8443); plain HTTP only answers with a `308` redirect. OpenRoost normally uses its
own self-signed certificate, so the app should **pin** it: on first connection show the SHA-256 fingerprint
(`GET /api/v1/status` → `tlsFingerprint`, also in Settings → System → About and the server log), let the user
confirm it matches, then accept only that certificate. If the owner installs a CA-signed certificate
(`OPENROOST_TLS_CERT`), normal verification works. TLS 1.2+ only.

Each address may make 600 requests a minute (`429` with `Retry-After` beyond that) and hold 8 live streams.

## Signing in

The app must sign in to an account that exists on the server; it gets exactly that account's role, checked on
every request.


```http
POST /api/v1/auth/token
{"username": "...", "password": "...", "deviceName": "Pixel 9", "totp": "123456"}
→ 200 {"token": "ort_…", "tokenType": "Bearer", "expiresIn": 7776000, "user": {...}}
→ 200 {"mfaRequired": true, "ticket": "..."}      (two-factor on and no "totp" sent)
     then POST /api/v1/auth/totp {"ticket", "code"} → the token response
```

Send `Authorization: Bearer ort_…` on every request. Tokens slide: each use extends them to 90 days (at most one
year from sign-in). They appear in the user's device list (`GET /api/v1/me/sessions`) and can be revoked there or
with `POST /api/v1/auth/logout`. Bearer requests don't need the `X-OpenRoost` CSRF header that browsers send.
Failed sign-ins are throttled (5 per 15 minutes per address and per username → `429` with `Retry-After`).

### Forgotten password

```http
POST /api/v1/auth/reset-request {"login": "<username or email>"}
→ 200 {"ok": true, "message": "If that account has an email address, a reset link is on its way. …"}
```

Always the same answer, so it can't be used to find accounts; throttled per address and per account. The email links
to the dashboard (`<web address>/?reset=<token>`, single use, 30 minutes); the app may instead read the token and call
`POST /api/v1/auth/reset {"token", "password"}`. A reset signs the account out everywhere and emails a
"password changed" notice.

### Invite links

An owner creates a link (`POST /api/v1/users/invites`); the token is in the link only, shown once. The invitee:

```http
POST /api/v1/auth/invite        {"token"}                       → 200 {"site", "role", "by", "expires", "email"} | 404
POST /api/v1/auth/invite/accept {"token", "username", "password", "display"?, "email"?, "deviceName"?}
```

Accepting creates the account with the invite's role and signs in: a cookie, or with `deviceName` a bearer token like
`/auth/token`. A link works once; wrong tokens are throttled per address.

## Reading state

| Call | Returns |
|---|---|
| `GET /api/v1/overview` | Home screen in one call: hub, arm state, active alerts, sensor counts, listener |
| `GET /api/v1/hub` | Online, power, backup battery, Wi-Fi, cellular, climate, firmware |
| `GET /api/v1/arm` | `state` (hub `as`: 0 / 2 / 8 / 4), `mode`, `countdown {kind, ends, seconds}`, `lastDisarm` |
| `GET /api/v1/alerts` | Alarms with `active` (still happening) — stay until acknowledged |
| `GET /api/v1/sensors`, `/sensors/{id}` | Type, name, room, state, battery %, signal, firmware, `missing` |
| `GET /api/v1/events?limit=&before=&kind=&since=` | History, newest first; page with `before=<id>` |
| `GET /api/v1/pairing` | Pairing window and newly found sensors |
| `GET /api/v1/settings` | Settings; secrets only as `secretsSet` flags |
| `GET /api/v1/features` | Every feature with `supported` or `planned` |
| `GET /api/v1/version` | `version`, `commit`, `latest`, `updateAvailable`, `releaseUrl` (owners: `POST /api/v1/version/check`) |

Times are Unix seconds. Owners see raw hub messages on events (`raw`); members and viewers don't.

## Live updates

`GET /api/v1/stream` is a server-sent-events stream (`text/event-stream`). It starts with `hello` (the overview),
then sends `hub`, `arm`, `sensor`, `event`, `alert`, `pairing` and `listener` messages whose `data` is the same
JSON shape as the REST endpoints. Comment lines (`: keepalive`) arrive every ~15 s. On reconnect, reload the
REST endpoints you show.

## Acting

| Call | Who |
|---|---|
| `POST /api/v1/alerts/{kind}/ack` | member, owner — stops repeat notifications |
| `PATCH /api/v1/sensors/{id}` `{"name", "room"}` | owner |
| `DELETE /api/v1/sensors/{id}` | owner — hides it; `PATCH {"removed": false}` undoes |
| `POST /api/v1/pairing/start` / `stop` | owner |
| `PUT /api/v1/settings` `{"settings": {...}, "clear": [...]}` | owner |
| `POST /api/v1/notify/test/{email|ntfy|webhook|matrix}` | owner — `{"to": "…"}` for one email address |
| `POST /api/v1/hub/claim` | owner — trust the hub that is connected now |
| `GET /api/v1/services/checks`, `POST /api/v1/services/fix/{dns|nat}` | owner — redirect health; for a Pi-hole OpenRoost doesn't run, `fix/dns` returns `{"manual": true, "lines", "docker", "native"}` |
| `GET /api/v1/debug/wire?limit=&after=` | owner — protocol log (every packet to/from the hub); live as `wire` events on the stream, owners only |
| `GET /api/v1/users/invites`, `POST /api/v1/users/invites`, `DELETE /api/v1/users/invites/{id}` | owner — `{"role", "hours" (1–168), "note"?, "email"? (send it)}` → `{"link", "invite", "emailed"}` |
| `GET /api/v1/escalations` | viewer — emergency countdowns of the last 24 h: `id, kind, label, detail, start, deadline, secs, state` (`pending`/`cancelled`/`sent`), `by, via`, `told` (contact names, once sent); live as `escalation` events on the stream. Silent (hostage-PIN) ones only for owners |
| `POST /api/v1/escalations/{id}/cancel` | member — cancel a pending countdown (`409` if too late) |
| `POST /api/v1/escalations/peek`, `/cancel` `{"token"}` | public — the cancel link from a countdown email (the token is the permission; throttled) |
| `GET /api/v1/admin/key` | owner — master key id, `fromEnv`, `accountsOnOldKey` |
| `POST /api/v1/admin/rotate-key` | owner — `{"password"}`; re-encrypts every secret, ends every session but a new one for the caller (cookie, or `token` for an app) |
| `GET /api/v1/notify/matrix/e2ee` | owner — Matrix encryption: `available`, `ready`, `device`, `crossSigned`, `fingerprint` |
| `GET /api/v1/services/bundled` | owner — is OpenRoost's own Pi-hole / mail relay running |
| `GET /api/v1/me/sessions`, `DELETE /api/v1/me/sessions/{id}` | any — this account's browsers and app devices |
| `POST /api/v1/me/totp/setup`, `/enable`, `/disable` | any — two-factor codes |

Roles: **owner** (everything), **member** (acknowledge alarms; arm/disarm once supported), **viewer** (read only).

## Planned features

Planned endpoints already exist so the app can be built against them now. Today they answer:

```http
HTTP/1.1 501
{"error": "Planned, unsupported", "feature": "hub.arm", "status": "planned", "summary": "Arming and disarming from the app: …"}
```

| Endpoint | Feature |
|---|---|
| `POST /api/v1/arm` `{"mode": "off" | "home" | "away", "pin"?}` | `hub.arm` |
| `GET` / `PUT /api/v1/hub/pins` | `hub.pins` |
| `PUT /api/v1/hub/settings` (entry/exit delay, chime) | `hub.delays` |
| `PUT /api/v1/sensors/{id}/alert-mode` | `sensors.alertMode` |
| `POST /api/v1/sensors/{id}/unpair` | `sensors.unpair` |
| `POST /api/v1/hub/wifi/scan`, `/provision` | `hub.wifi` |

Show these as unavailable when `GET /api/v1/features` says `planned`; when a feature flips to `supported`, the same
endpoint starts working with no app update.

## Errors

JSON `{"error": "..."}` with the usual codes: `400` (with `fields` for validation), `401` sign in, `403` role,
`404`, `409` conflict, `413` too large, `429` throttled, `501` planned.
