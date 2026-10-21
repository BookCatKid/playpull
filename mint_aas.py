#!/usr/bin/env python3
"""Mint an AAS master token by reproducing the on-device Play sign-in flow.

Why this exists: Google retired raw password auth on android.clients.google.com/auth
(BadAuthentication regardless of device identity). What still works - and what a real
Android device does - is the hosted web flow (EmbeddedSetup) followed by an oauth_token
-> AAS exchange. This script drives that flow in a real browser engine.

Requirements: playwright (+chromium), gpsoauth. Run under a real display or xvfb:
    xvfb-run -a python3 mint_aas.py
Headless chromium is rejected at the email step ("browser or app may not be secure").

You will be asked for email + password (or point EMAIL_FILE/PASSWORD_FILE at files).
If the account has 2SV, complete the challenge in the visible browser window
(or run headful and type it yourself). The script waits for the flow to complete,
harvests the single-use oauth_token cookie, exchanges it for an AAS token, and
writes ./aas_token (mode 0600).
"""
import getpass, json, os, sys, time
import gpsoauth
from playwright.sync_api import sync_playwright

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
DIR = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(DIR, 'config.json')
try:
    CFG = json.load(open(CFG_PATH))
except FileNotFoundError:
    # first run: start from the shipped defaults; written back after the mint
    CFG = json.load(open(os.path.join(DIR, 'config.example.json')))

def read_secret(prompt, envfile):
    p = os.environ.get(envfile)
    if p:
        return open(p).read().strip()
    return getpass.getpass(prompt)

email = CFG.get('email') or input('email: ')
password = read_secret('password: ', 'PASSWORD_FILE')

with sync_playwright() as pw:
    b = pw.chromium.launch(headless=False, args=["--disable-blink-features=AutomationControlled", "--no-sandbox"])
    ctx = b.new_context(user_agent=UA, viewport={"width": 1280, "height": 800},
                        locale="en-US", timezone_id="America/Los_Angeles")
    pg = ctx.new_page()
    pg.goto("https://accounts.google.com/EmbeddedSetup", timeout=45000)
    pg.wait_for_selector('#identifierId', timeout=30000)
    pg.fill('#identifierId', email)
    pg.keyboard.press("Enter")
    pg.wait_for_selector('input[type="password"]', timeout=20000)
    pg.fill('input[type="password"]', password)
    pg.keyboard.press("Enter")
    print("password submitted - complete any 2SV challenge in the browser window...")

    # wait for the consent speedbump, then click the "I agree" button (exact match;
    # a plain text= click can hit the sentence "'I Agree,'" in the body instead)
    deadline = time.time() + 300
    while time.time() < deadline:
        if 'embeddedsigninconsent' in pg.url:
            break
        time.sleep(2)
    else:
        sys.exit("timed out waiting for the consent page - still on %s" % pg.url)
    pg.click('button:has-text("I agree")', timeout=15000)

    # oauth_token is minted at flow completion; poll cookies until it appears.
    # NB: the cookie is HttpOnly - document.cookie cannot see it, the context API can.
    oauth = None
    deadline = time.time() + 120
    while time.time() < deadline:
        for c in ctx.cookies():
            if c['name'] == 'oauth_token':
                oauth = c['value']
        if oauth:
            break
        time.sleep(2)
    if not oauth:
        sys.exit("no oauth_token cookie - flow did not complete (url=%s)" % pg.url)
    ctx.close()

r = gpsoauth.exchange_token(email, oauth, CFG.get('gsf_id') or '0')
if 'Error' in r:
    sys.exit("exchange failed: %s (oauth_token is single-use; rerun mint_aas.py)" % r)
out = os.path.join(DIR, 'aas_token')
open(out, 'w').write(r['Token'])
os.chmod(out, 0o600)
print("AAS token written to", out)
# the only user input is the sign-in itself: persist it so nothing needs editing
CFG['email'] = email
json.dump(CFG, open(CFG_PATH, 'w'), indent=2, sort_keys=True)
os.chmod(CFG_PATH, 0o600)
print("config.json ready (defaults + your email - nothing to edit)")
if not CFG.get('gsf_id'):
    print("next step: python3 pull.py init   (one-time device registration)")
