"""HTML emails that match the web app (Hearth colours and type), with a plain-text alternative.

Email clients ignore <style> blocks and web fonts unevenly, so everything is inline and table-based, with safe
font fallbacks (Georgia for the Fraunces headings, system sans for Figtree).
"""
import html

C = {'bg': '#f5efe6', 'card': '#fffcf7', 'card2': '#f9f3ea', 'line': '#e8ddcf', 'ink': '#2c241f', 'muted': '#8a7b6e',
     'accent': '#c8553d', 'ok': '#4f8a6b', 'warn': '#cf8a2b', 'crit': '#c2362b', 'water': '#3a78bb'}
SEV = {'crit': (C['crit'], 'Alarm'), 'warn': (C['warn'], 'Warning'), 'info': (C['ok'], 'Update')}
KIND_COLOR = {'leak': C['water'], 'duress': '#6b3fa0'}
SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
SERIF = "Georgia,'Times New Roman',serif"
e = html.escape


def _page(site, eyebrow, color, title, body_html, button=None, footer=''):
    btn = ''
    if button:
        btn = (f'<tr><td style="padding:8px 32px 28px"><a href="{e(button[1])}" style="display:inline-block;background:{C["accent"]};color:#fff;'
               f'text-decoration:none;font:600 15px {SANS};padding:12px 22px;border-radius:999px">{e(button[0])}</a></td></tr>')
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light">
<title>{e(title)}</title></head>
<body style="margin:0;padding:0;background:{C['bg']}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{C['bg']};padding:28px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px">
<tr><td style="padding:0 8px 16px"><table role="presentation" cellpadding="0" cellspacing="0"><tr>
  <td style="width:36px;height:36px;background:{C['accent']};border-radius:12px;text-align:center;vertical-align:middle;font:700 18px {SERIF};color:#fff">O</td>
  <td style="padding-left:10px;font:650 20px {SERIF};color:{C['ink']}">OpenRoost360</td>
  <td style="padding-left:10px;font:500 13px {SANS};color:{C['muted']}">{e(site)}</td></tr></table></td></tr>
<tr><td style="background:{C['card']};border:1px solid {C['line']};border-radius:20px;overflow:hidden">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
  <tr><td style="height:6px;background:{color};font-size:0;line-height:0">&nbsp;</td></tr>
  <tr><td style="padding:26px 32px 4px;font:700 12px {SANS};letter-spacing:.08em;text-transform:uppercase;color:{color}">{e(eyebrow)}</td></tr>
  <tr><td style="padding:2px 32px 10px;font:650 26px/1.2 {SERIF};color:{C['ink']}">{e(title)}</td></tr>
  <tr><td style="padding:0 32px 22px;font:400 15px/1.55 {SANS};color:{C['ink']}">{body_html}</td></tr>
  {btn}
  </table></td></tr>
<tr><td style="padding:16px 12px;font:400 12px/1.5 {SANS};color:{C['muted']};text-align:center">{footer}Sent by your OpenRoost360 server · not affiliated with Roost</td></tr>
</table></td></tr></table></body></html>"""


def alert(site, kind, title, detail, sev='info', when='', link=None, contact_note=''):
    color, label = SEV.get(sev, SEV['info'])
    color = KIND_COLOR.get(kind, color)
    rows = f'<p style="margin:0 0 12px">{e(detail)}</p>'
    if when: rows += f'<p style="margin:0;font-size:13px;color:{C["muted"]}">{e(when)}</p>'
    if contact_note: rows += f'<p style="margin:14px 0 0;padding:10px 14px;background:{C["card2"]};border-radius:12px;font-size:13px;color:{C["muted"]}">{e(contact_note)}</p>'
    html_body = _page(site, label, color, title, rows, ('Open OpenRoost', link) if link else None)
    text = f'{title}\n\n{detail}\n{when}\n' + (f'\n{contact_note}\n' if contact_note else '') + (f'\nOpen OpenRoost: {link}\n' if link else '') + '\n— OpenRoost360'
    return text, html_body


def reset(site, name, link, minutes):
    body = (f'<p style="margin:0 0 12px">Hi {e(name)}, someone (hopefully you) asked to reset your OpenRoost360 password.</p>'
            f'<p style="margin:0 0 12px">The link works once and expires in {minutes} minutes. If you didn\'t ask for this, ignore this email: your password stays the same.</p>')
    text = (f'Hi {name},\n\nsomeone (hopefully you) asked to reset your OpenRoost360 password. Open this link to choose a new one '
            f'(it works once and expires in {minutes} minutes):\n\n{link}\n\nIf you didn\'t ask for this, ignore this email.\n\n— OpenRoost360')
    return text, _page(site, 'Account', C['accent'], 'Reset your password', body, ('Choose a new password', link))


def password_changed(site, name, ip):
    body = (f'<p style="margin:0 0 12px">Hi {e(name)}, the password for your OpenRoost360 account was just changed (from {e(ip)}), '
            f'and your other devices were signed out.</p><p style="margin:0">If this wasn\'t you, ask an owner of your OpenRoost to reset it now.</p>')
    text = f'Hi {name},\n\nthe password for your OpenRoost360 account was just changed (from {ip}) and your other devices were signed out.\nIf this wasn\'t you, ask an owner to reset it now.\n\n— OpenRoost360'
    return text, _page(site, 'Account', C['accent'], 'Your password was changed', body)


def test(site):
    body = ('<p style="margin:0 0 12px">If you can read this, email alerts from OpenRoost360 reach you. Alarms, leaks and other events you route to email will look like this.</p>')
    return 'If you can read this, email alerts from OpenRoost360 reach you.\n\n— OpenRoost360', _page(site, 'Test', C['ok'], 'Email alerts work', body)


ROLE_WORDS = {'owner': 'an owner (full control)', 'member': 'a member (sees everything, acknowledges alarms)', 'viewer': 'a viewer (sees status and history)'}


def invite(site, inviter, role, link, hours):
    body = (f'<p style="margin:0 0 12px">{e(inviter)} invited you to the OpenRoost360 alarm system for <b>{e(site)}</b>, as {e(ROLE_WORDS.get(role, role))}.</p>'
            f'<p style="margin:0 0 12px">Open the link to choose a username and password. It works once and expires in {hours} hours.</p>')
    text = (f'{inviter} invited you to the OpenRoost360 alarm system for {site}, as {ROLE_WORDS.get(role, role)}.\n\n'
            f'Open this link to choose a username and password (it works once and expires in {hours} hours):\n\n{link}\n\n— OpenRoost360')
    return text, _page(site, 'Invitation', C['accent'], 'You\'re invited', body, ('Create your account', link))


def joined(site, name, username, role):
    body = f'<p style="margin:0">{e(name)} (@{e(username)}) accepted an invite and joined as {e(role)}. You can change their role or remove them under Settings → Account → Household members.</p>'
    return f'{name} (@{username}) accepted an invite and joined {site} as {role}.\n\n— OpenRoost360', _page(site, 'Account', C['accent'], 'Someone joined', body)


def key_rotated(site, by, ip):
    body = (f'<p style="margin:0 0 12px">{e(by)} rotated the master key of your OpenRoost360 server (from {e(ip)}). Every secret was re-encrypted and everyone was signed out.</p>'
            f'<p style="margin:0">Download a new backup now (Settings → System → Backup): older backups still work, but contain the old key.</p>')
    return (f'{by} rotated the master key of your OpenRoost360 server (from {ip}). Everyone was signed out. Download a new backup now.\n\n— OpenRoost360',
            _page(site, 'Security', C['accent'], 'Master key rotated', body))


def countdown(site, label, detail, secs, until, link):
    """Emergency countdown: the household has `secs` seconds to cancel before the emergency contacts are told."""
    instr = f'PLEASE RESPOND WITHIN {secs} SECONDS TO CANCEL THE EMERGENCY EMAIL / MATRIX MESSAGE'
    body = (f'<p style="margin:0 0 14px;font:700 15px/1.45 {SANS};color:{C["crit"]}">{e(instr)}</p>'
            f'<p style="margin:0 0 12px">{e(detail)}</p>'
            + (f'<p style="margin:0">Click the button below by <b>{e(until)}</b> ({secs} seconds) to cancel the emergency email / Matrix message to your emergency contacts. '
               'If nobody cancels, they are told automatically.</p>' if link else
               f'<p style="margin:0">Reply "N" in Matrix or cancel in the OpenRoost app by <b>{e(until)}</b>. If nobody cancels, the emergency contacts are told automatically.</p>'))
    text = (f'{label}\n{instr}\n\n{detail}\n\n'
            + (f'Open this link by {until} ({secs} seconds) to cancel the emergency email / Matrix message to your emergency contacts:\n{link}\n' if link else
               f'Reply "N" in Matrix or cancel in the OpenRoost app by {until}.\n')
            + '\nIf nobody cancels, the emergency contacts are told automatically.\n\n— OpenRoost360')
    return text, _page(site, 'Emergency', C['crit'], label, body, ('Cancel the emergency messages', link) if link else None)


def countdown_result(site, title, body_text, cancelled):
    color = C['ok'] if cancelled else C['crit']
    return f'{title}\n{body_text}\n\n— OpenRoost360', _page(site, 'Emergency', color, title, f'<p style="margin:0">{e(body_text)}</p>')
