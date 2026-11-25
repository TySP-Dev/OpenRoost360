# Installing OpenRoost360

You need a Linux server on the same network as the SmartBase (Docker + Docker Compose), a Pi-hole v6 (yours, or the
one OpenRoost can run), and a way to send email (optional but recommended). About 20 minutes.

## 1. Get it and configure

```bash
git clone https://git.tysstech.com/TySS-Dev/OpenRoost360.git
cd OpenRoost360
cp .env.example .env
nano .env
```

The defaults work for most homes. Things you might change:

| Setting | When |
|---|---|
| `TZ` | Your time zone, for logs |
| `OPENROOST_HTTPS_PORT` (8443), `OPENROOST_HTTP_PORT` (8362), `OPENROOST_LISTENER_PORT` (8883) | If something else uses these ports |
| `OPENROOST_HOSTS` | If you open OpenRoost by a host name that isn't an IP address or `*.local` / `*.lan` / `*.home.arpa` (also needed for Authentik sign-in through a domain) |
| `OPENROOST_HUB_IP` | The hub's IP address (give it a DHCP reservation). Optional: setup asks for it, and OpenRoost can spot it in Pi-hole's query log |
| `OPENROOST_DNS` | DNS server(s) for OpenRoost's own lookups (Matrix, email, Authentik). Blank = its own Pi-hole if that profile runs, else the host's `/etc/resolv.conf`. Compose can't set `dns:` with host networking, hence this |
| `COMPOSE_PROFILES` | Add `pihole` and/or `mailrelay` to have OpenRoost run them for you (steps 3 and 4) |

> **Already running the research listener (`roost_listen.py`)?** Stop it first: it uses port 8883 too.

## 2. Start it

```bash
docker compose up -d --build
docker compose logs openroost
```

The log shows the **first-time setup code** and the HTTPS certificate fingerprint. Open
`https://<server-ip>:8443/`. Your browser warns once because the certificate is OpenRoost's own: check the
fingerprint matches the log and continue. The setup wizard walks you through the rest; the steps below explain what
it asks for.

The container starts with the server and re-adds the hub's port redirect every time, so it survives reboots.
Data lives in `./data` (owned by root). **Back up `data/master.key` together with the rest of `data/`**, or download
an encrypted backup from Settings → System → Backup.

## 3. Pi-hole

The hub must use a Pi-hole for DNS, and that Pi-hole must answer Roost's two cloud names with this server's address.

### Your own Pi-hole (v6)

1. In Pi-hole: **Settings → Web interface / API → Configure app password**, and copy it. In setup, choose
   **My existing Pi-hole** and enter its address (e.g. `http://192.168.1.2/admin`) and that app password.
2. Pi-hole only accepts the two DNS lines through its own settings, not from other apps, so **Check this server →
   Fix it** shows them with copy buttons, together with a command that keeps any lines you already have:

   ```bash
   # Pi-hole in Docker (replace <pihole-container>; the command from the wizard includes your existing lines)
   docker exec <pihole-container> pihole-FTL --config misc.dnsmasq_lines \
     '["address=/us-central1-mqtt.clearblade.com/<server-ip>","address=/us-central1-roostprod.cloudfunctions.net/<server-ip>"]'
   docker exec <pihole-container> pihole reloaddns
   ```

   Then press **Run checks again**: OpenRoost asks your Pi-hole for both names and confirms they point here.
3. Make sure the hub uses this Pi-hole for DNS: either your router hands it out to everyone, or give the hub a DHCP
   reservation with this Pi-hole as its DNS server.

### OpenRoost's own Pi-hole

Only if you don't run one already; port 53 must be free on this server.

```bash
# in .env
COMPOSE_PROFILES=pihole
PIHOLE_PASSWORD=<a long random password>      # its admin page: http://<server>:8053/admin
docker compose up -d
```

In setup choose **The one included with OpenRoost**. OpenRoost writes the two DNS lines into it and restarts its DNS by
itself. Then point your router's DNS (or just the hub's) at this server.

## 4. Email

Choose one in setup (change it later under Settings → Notifications):

- **Your mail relay** (e.g. Postfix): its address and port, sign-in if it needs one, and a From address it may send as.
  It must allow this server to relay.
- **An email account**: Gmail or iCloud (needs an *app password*), or any SMTP server.
- **OpenRoost's own relay** (a Postfix container that hands mail to Resend or another service):

  ```bash
  # in .env
  COMPOSE_PROFILES=pihole,mailrelay        # or just mailrelay
  RELAY_UPSTREAM=[smtp.resend.com]:587
  RELAY_USERNAME=resend
  RELAY_PASSWORD=re_xxxxxxxx               # your Resend API key
  RELAY_SENDER_DOMAINS=yourdomain.com      # verified in Resend
  docker compose up -d
  ```

Every option has a **Send a test email** button. Alerts and test emails use an HTML layout that matches the
dashboard. Password-reset links and "your password was changed" notices also go by email, to each user's own address
(Settings → Account → Profile), using the **web address** saved during setup (Settings → System → Web address).

## 5. Matrix (optional)

Create a bot account on your homeserver (e.g. `@openroost:example.org`), create a room for alerts (encrypted or not)
and invite the bot (it accepts the invite by itself). In setup (or Settings → Notifications → Matrix) enter the homeserver URL and bot account, sign the
bot in with its password, enter the room and press **Send a test message**. Distress alerts also go to each emergency
contact's Matrix ID as a direct message.

**Encryption.** When the bot signs in, OpenRoost gives its device end-to-end encryption keys and cross-signs it with
the bot's own account, using the password once. OpenRoost keeps only the access token and the keys, all encrypted on the
server. It notices by itself when a room is encrypted and encrypts its messages; with *Encrypt direct messages* on (the
default), new DMs to emergency contacts are created encrypted. Settings shows the bot device's fingerprint if you want
to verify it in Element. Each time the bot signs in again it becomes a new device, and new DMs are created.

**Homeserver address.** You can enter your server name (`https://example.org`): OpenRoost follows its
`/.well-known/matrix/client` to the real homeserver (e.g. `https://matrix.example.org`) and saves that.

## 6. Emergency countdown (optional)

Settings → Notifications → **Emergency countdown**. When a break-in, fire alarm or distress (hostage) PIN happens, the
people you list there are warned first and get a set time to cancel (default: break-in 60 s, fire 120 s, distress
PIN 60 s). Only after that are the **emergency contacts** told. The countdown message reads:

```
BREAK IN
PLEASE RESPOND "N" WITHIN 60 SECONDS TO CANCEL THE EMERGENCY EMAIL / MATRIX MESSAGE
```

It goes to each listed person by email, with their own cancel link, and as a Matrix DM. It also goes to the household
room if you leave that on. They cancel by replying **N** (in that room or DM; only listed Matrix IDs count), by opening
the link, or with **Cancel** on the dashboard. Afterwards everyone who got the countdown (room, DMs and email) gets a
follow-up: either *CANCELLED: BREAK IN — cancelled by …*, or *EMERGENCY MESSAGES SENT: BREAK IN* with who was told and
how (e.g. "Nana (email + Matrix)") and anyone who couldn't be reached. The dashboard and history show the same. A countdown only runs when someone can cancel it and a contact would be told; otherwise alarms go out
immediately as before. If the server restarts during a countdown, anything overdue is sent at start-up. Email cancel
links point to the web address saved during setup (Settings → System → Web address), so make sure it works from
people's phones.

A distress PIN means someone may be under pressure, and anyone on the list can cancel. Keep the list to people who
wouldn't be with you, or turn the distress countdown off.

## 7. Find the hub

In setup, **Find your SmartBase** shows the hub as soon as it connects. If it's already on your Wi-Fi and using your
Pi-hole, it usually appears within a minute; otherwise unplug it for 10 seconds. OpenRoost then trusts only that hub.

**Port 443.** The hub talks to the cloud on port 443, so this server redirects the hub's port 443 to the listener
(an iptables rule; the container has `NET_ADMIN` for it). The rule needs the hub's address, which OpenRoost gets from
(any of) the setup step's **Hub IP** box, `OPENROOST_HUB_IP` in `.env`, Settings → Hub & network, or by spotting the
hub in Pi-hole's query log. From then on it checks the rule every minute and re-adds it after reboots, firewall
reloads and address changes: no manual `iptables` command is needed. You name your sensors next; they appear as the hub reports them
(open a door to see which is which).

If the hub doesn't show up:

- `dig +short us-central1-roostprod.cloudfunctions.net @<your-pihole>` must return this server's address.
- Pi-hole's query log should show the hub asking for that name.
- Settings → Hub & network → **Redirect health** checks the listener, time reply, DNS, the port rule and the hub session.
- The hub's light ring should be solid (blinking means pairing or setup mode).

## 8. Household and sign-in

Add family under Settings → Account → Household members (owner, member or viewer): either set a temporary password
yourself, or create an **invite link** (it can be emailed for you) that works once and lets them choose their own
username and password. Optional: two-factor codes for each
account, and Authentik single sign-on (the redirect URI to paste into Authentik is shown there).

**Authentik.** Create an OAuth2/OpenID provider (confidential client; a signing key is optional) with the redirect URI
from Settings → Account → Single sign-on, and an application for it. Fill in the issuer
(`https://auth.example.com/application/o/<slug>/`), client ID and secret, press **Test connection** and save. Then, still
signed in with your password, use **Link Authentik** under *Your Authentik account*, so Authentik opens your existing
owner account. Groups `openroost-admins` / `openroost-members` set the role (no groups claim at all: the role isn't
touched). If you reach OpenRoost by a domain name, list it in `OPENROOST_HOSTS`.

## Behind a reverse proxy (e.g. Nginx Proxy Manager)

Either proxy to `https://<server>:8443` (it has its own certificate), or set `OPENROOST_TLS=off`, proxy to
`http://<server>:8362`, and list the proxy's address in `OPENROOST_PROXY_IPS` so OpenRoost trusts its
`X-Forwarded-For` / `X-Forwarded-Proto`. Add the proxy's host name to `OPENROOST_HOSTS`. Your own certificate:
put it in `./data` and set `OPENROOST_TLS_CERT=/data/<file>.crt` and `OPENROOST_TLS_KEY=/data/<file>.key`.

## Updating

Owners see **Update available** in the dashboard when a new release tag exists. Then:

```bash
cd OpenRoost360
./update.sh            # newest release; ./update.sh main for the newest development version
```

It fetches the release with git, rebuilds the image and restarts the container. Everything lives in `./data`
(database with settings, sensors, names, users; master key; certificates) and `.env`, neither of which git or the
rebuild touches. The database only ever gains tables and columns, and before a new version (or commit) first opens it,
OpenRoost copies it to `data/backups/` (the last 5 are kept). (If your copy of the repository is private, set
`OPENROOST_UPDATE_TOKEN` in `.env` so the update check can read the tags.)

**Releases** are git tags named `vMAJOR.MINOR.PATCH` matching `openroost/__init__.py`. Until the first one is pushed,
the update check compares with the newest commit on `main` instead. To publish one:

```bash
git tag v0.2.0 && git push origin v0.2.0
```

## Without Docker

```bash
pip install -r requirements.txt
./run.sh                # ./run.sh stop · ./run.sh fg
sudo iptables -t nat -I PREROUTING 1 -s <hub-ip> -p tcp --dport 443 -j REDIRECT --to-ports 8883
```

(Or run it as root so it manages that rule itself.) The bundled Pi-hole and mail relay need Docker.

## Rotating the master key

`data/master.key` encrypts every stored secret. If it, or a backup, may have leaked: Settings → System → About →
**Rotate master key** (owners, needs your password). A new key re-encrypts everything, everyone else is signed out,
and pending reset and invite links stop working. Passwords keep working, and each account moves to the new key at its
next sign-in. Download a fresh backup afterwards. If OpenRoost was interrupted halfway, it finishes or undoes the switch
at the next start. A key set with `OPENROOST_MASTER_KEY` can't be rotated from the dashboard.

## Restoring a backup

```bash
docker compose down
docker compose run --rm --entrypoint python openroost -m openroost restore /data/<backup>.orb --data /data
docker compose up -d
```

(Copy the `.orb` file into `./data` first; it asks for the backup passphrase.)
