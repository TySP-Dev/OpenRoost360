# roostfiles-certs

Copies of the two public bundles from `roostfiles.s3.amazonaws.com` (fetched 2026-11-22).
Format is documented in `docs/PROTOCOL.md` → "Cert/endpoint bundle".

| File | Bundle version | `url.txt` (MQTT broker) | MD5 (= S3 ETag) |
|---|---|---|---|
| `acert.bin` | `0.0.7` (matches hub `cv`) | `us-central1-mqtt.clearblade.com` | `88baa3a02fe00f24920add4e441d6b1b` |
| `bcert.bin` | `1.1.1` | `iotcore.getroost.com` | `8d7718e8d3d306ce20a5ec9ccdc7fc4e` |

Each contains `wcert.bin` (Wi-Fi module CA store), `ccert.bin` (root CA PEMs) and `url.txt`.

**Only `acert.bin` is safe to serve to the hub** (it's what the hub already has; tested
2026-11-22). **Do not serve `bcert.bin`:** it would set the hub's MQTT broker to
`iotcore.getroost.com`, which is not redirected, and could take the hub off the local listener.
To serve a file, put it in `files/` next to `roost_listen.py`.
