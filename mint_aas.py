#!/usr/bin/env python3
"""Mint an AAS master token by signing into Google in a real browser.

Google retired raw password auth on android.clients.google.com/auth
(BadAuthentication regardless of device identity), so sign-in uses the hosted
web flow (EmbeddedSetup), the same flow a real Android device runs, followed by
an oauth_token -> AAS exchange.

Requirements: playwright (+chromium), gpsoauth. Run under a real display (macOS/desktop: python3 mint_aas.py) or, on a headless Linux box, xvfb:
    xvfb-run -a python3 mint_aas.py
Headless chromium is rejected at the email step ("browser or app may not be secure").

Setup asks exactly one question: your Google email. The browser opens on Google's
sign-in page with that email filled in; complete the sign-in in the window
(password, 2SV, whatever Google asks). The script never sees your password. On
completion it exchanges the single-use oauth_token cookie for an AAS token and
writes ./aas_token (0600).
"""
import json, os, sys, time
import gpsoauth
from playwright.sync_api import sync_playwright, Error as PWError

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")
DIR = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(DIR, 'config.json')
try:
    CFG = json.load(open(CFG_PATH))
except FileNotFoundError:
    # first run: start from the shipped defaults; written back after the mint
    CFG = json.load(open(os.path.join(DIR, 'config.example.json')))

email = CFG.get('email') or input('Google email: ')

with sync_playwright() as pw:
    b = pw.chromium.launch(headless=False, args=["--disable-blink-features=AutomationControlled", "--no-sandbox"])
    ctx = b.new_context(user_agent=UA, viewport={"width": 1280, "height": 800},
                        locale="en-US", timezone_id="America/Los_Angeles")
    pg = ctx.new_page()
    pg.goto("https://accounts.google.com/EmbeddedSetup", timeout=45000)
    pg.wait_for_selector('#identifierId', timeout=30000)
    pg.fill('#identifierId', email)
    pg.keyboard.press("Enter")
    print("sign in in the browser window (including I agree if a consent screen appears); the script never sees your password")

    # Completion is the single-use HttpOnly oauth_token cookie; poll the
    # context cookie jar for a non-empty value (document.cookie can't see it).
    oauth = None
    deadline = time.time() + 900
    while time.time() < deadline:
        try:
            cookies = ctx.cookies()
        except PWError as e:
            if 'closed' in str(e).lower():
                sys.exit("browser closed before sign-in completed; rerun mint_aas.py")
            raise
        for c in cookies:
            if c['name'] == 'oauth_token' and c['value']:
                oauth = c['value']
        if oauth:
            break
        time.sleep(2)
    if not oauth:
        try:
            url = pg.url
        except Exception:
            url = 'unknown'
        sys.exit("no oauth_token cookie - flow did not complete (url=%s)" % url)
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

