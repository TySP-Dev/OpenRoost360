"""Feature registry: what OpenRoost360 can do today and what is planned.

The dashboard greys out planned features ("Planned, unsupported") and the API answers their
endpoints with 501 + {"feature": id, "status": "planned"}, so the mobile app can show the same
state and start working the day a feature ships, with no app update.
"""
SUPPORTED, PLANNED = 'supported', 'planned'

FEATURES = {
    # ---- hub (decoded in docs/PROTOCOL.md)
    'hub.status':        (SUPPORTED, 'Live hub status: power, backup battery, Wi-Fi, cellular, climate, firmware'),
    'hub.events':        (SUPPORTED, 'Event history and raw hub messages'),
    'hub.alerts':        (SUPPORTED, 'Intrusion, fire, panic, hostage-PIN and leak alerts'),
    'hub.armState':      (SUPPORTED, 'Arm state with exit and entry delays (read-only)'),
    'sensors.list':      (SUPPORTED, 'Sensors with battery, signal, firmware and Missing status'),
    'sensors.edit':      (SUPPORTED, 'Name sensors, set their room, remove them from OpenRoost'),
    'sensors.pairing':   (SUPPORTED, 'New sensors found while the hub is in pairing mode'),
    'hub.arm':           (PLANNED, 'Arming and disarming from the app: the hub\'s command format is not known yet'),
    'hub.pins':          (PLANNED, 'Keypad PINs: needs the hub\'s settings (/config) format'),
    'hub.delays':        (PLANNED, 'Entry and exit delays: needs the hub\'s settings (/config) format'),
    'hub.chime':         (PLANNED, 'Door chime: needs the hub\'s settings (/config) format'),
    'sensors.alertMode': (PLANNED, 'Per-sensor alert modes: needs the hub\'s settings (/config) format'),
    'sensors.unpair':    (PLANNED, 'Unpairing a sensor from the hub: command not known yet'),
    'hub.wifi':          (PLANNED, 'Wi-Fi setup and moving the hub to a new network (soft-AP provisioning)'),
    # ---- server services
    'pihole.existing':   (SUPPORTED, 'Use an existing Pi-hole (v6): checks it and gives the misc.dnsmasq_lines to add'),
    'pihole.bundled':    (SUPPORTED, 'OpenRoost\'s own Pi-hole (docker compose --profile pihole)'),
    'net.redirect':      (SUPPORTED, 'Redirect health: DNS lines, port 443 → 8883 rule, listener, hub session'),
    'mail.account':      (SUPPORTED, 'Email through an account (Gmail, iCloud, other SMTP)'),
    'mail.relayExisting': (SUPPORTED, 'Email through an existing mail relay'),
    'mail.relayStart':   (SUPPORTED, 'OpenRoost\'s own mail relay (docker compose --profile mailrelay)'),
    'auth.reset':        (SUPPORTED, 'Password reset by email'),
    # ---- notifications
    'notify.email':      (SUPPORTED, 'Email alerts'),
    'notify.ntfy':       (SUPPORTED, 'Push alerts through ntfy'),
    'notify.webhook':    (SUPPORTED, 'Signed webhooks'),
    'notify.matrix':     (SUPPORTED, 'Matrix / Element messages'),
    'notify.matrixE2ee': (SUPPORTED, 'Matrix end-to-end encrypted rooms and DMs (Olm/Megolm via vodozemac, cross-signed bot device)'),
    'notify.countdown':  (SUPPORTED, 'Emergency countdown: break-in, fire and distress PIN warn the household first; reply "N", the email link or the app cancels before contacts are told'),
    'notify.contacts':   (SUPPORTED, 'Family & emergency contacts with alert tiers'),
    # ---- accounts
    'auth.totp':         (SUPPORTED, 'Two-factor sign-in with an authenticator app'),
    'auth.oidc':         (SUPPORTED, 'Sign in with Authentik (OpenID Connect)'),
    'auth.proxy':        (SUPPORTED, 'Trusted reverse-proxy sign-in header'),
    'auth.invites':      (SUPPORTED, 'Invite links for household members (single use, expiring, optionally emailed)'),
    'admin.audit':       (SUPPORTED, 'Audit log of sign-ins and changes'),
    'dev.protocolLog':   (SUPPORTED, 'Live protocol log of everything the hub sends and receives (owners)'),
    'admin.backup':      (SUPPORTED, 'Encrypted backup download'),
    'admin.keyRotation': (SUPPORTED, 'Master-key rotation: re-encrypts every secret, signs everyone out'),
    'admin.updates':     (SUPPORTED, 'Checking for OpenRoost updates (release tags on the git server)'),
    'ui.kiosk':          (PLANNED, 'Wall-tablet mode: needs arming from the app'),
}


def listing():
    return [{'id': k, 'status': v[0], 'summary': v[1]} for k, v in FEATURES.items()]


def is_planned(fid):
    return FEATURES.get(fid, (PLANNED,))[0] == PLANNED
