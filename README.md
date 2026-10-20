# playpull - pure-python Google Play APK puller

Reproduces, in plain python, exactly what a real Android device does to sign in to
Google Play and download an app. No emulator, no rooted device, no Aurora dispensers.
Developed against a redroid (containerized Android 13) + MindTheGapps instance as the
reference implementation, with the flows verified against its own logs and account db.

## TL;DR

```
python3 mint_aas.py        # once: browser sign-in -> writes ./aas_token (needs 2SV once)
python3 pull.py check      # what version would Play serve this account/device?
python3 pull.py pull 90.01 # purchase + download all splits + verify signature
```

Setup: copy config.example.json to config.json, fill in email + gsf_id.
Deps: `pip install gpsoauth googleplay-api androguard playwright requests`
      (+ `python3 -m playwright install chromium` for minting)

## Why the existing python clients can't log in anymore

1. **The raw password channel is dead.** gpsoauth/gpapi/apkeep all do
   `Email + EncryptedPasswd -> POST android.clients.google.com/auth`. That returns
   `BadAuthentication` today regardless of device identity - tested with the real
   GSF id of a signed-in, Play-entitled device. Device trust is not the issue;
   the endpoint is simply retired for password auth.
2. **EmbeddedSetup needs a real browser engine.** A bare POST to
   accounts.google.com/EmbeddedSetup 400s because it lacks the flow ceremony
   (cookies, `TL` state tokens, JS challenges). Headless chromium is rejected at the
   email step ("This browser or app may not be secure"); full chromium (headed, or
   headless=new under xvfb) passes.
3. **Attestation is not the gate.** On the reference emulator (brand=redroid,
   userdebug/test-keys, no verified boot), Play Integrity token warmup fails and the
   first DroidGuard call fails - sign-in, checkin and app delivery all succeed anyway.

## The actual flow (as the device does it)

1. **EmbeddedSetup web flow** (GMS hosts it on-device; we host it in chromium):
   email -> password -> 2SV -> ToS consent ("I agree").
2. On completion Google sets an **`oauth_token` cookie**. It is HttpOnly - invisible
   to `document.cookie`, readable via the browser's cookie API/CDP - and **single-use**.
3. **Exchange**: `POST android.clients.google.com/auth` with `Token=<oauth_token>`,
   `ACCESS_TOKEN=1`, `service=ac2dm`, your `androidId` -> returns an **AAS master
   token** (`aas_et/...`). This is exactly what GMS stores in the device account db.
   gpsoauth.exchange_token() implements this endpoint correctly; it still works.
4. **Scope token**: exchange the AAS for
   `service=oauth2:https://www.googleapis.com/auth/googleplay`
   (app=com.android.vending). Note: modern Play uses this oauth2 scope - the legacy
   `service=android` token gets you DF-DFERH-01 on FDFE.
5. **FDFE calls** (android.clients.google.com/fdfe/...), with three requirements
   learned the hard way:
   - `uploadDeviceConfig` first;
   - a **current** Finsky User-Agent (stock gpapi sends 8.4.19 from 2017 - rejected);
   - a self-consistent device profile (see DEVICE_PROFILE in pull.py).
   Then: `details` -> `purchase` (free acquire, returns a downloadToken + the
   server-side record of the app's signing cert hash) -> `delivery` -> signed
   download URLs on play.googleapis.com (+ auth cookie), one per split.
6. **Verify** the APK yourself: package name, version string, and signer certificate.
   Sonos's current release cert: sha256 7C34EB3CFBDA05FAF56E8890A2ABBAC14B3036E6E4358849B98E8819B6B7B329
   (sha1 ae8894da0d05c79ba62c88ece076e86d779d800e, also returned by Play's purchase
   response). Aggregator mirrors sometimes serve re-signed installer stubs - check
   before trusting any mirror download.

## Notes

- The AAS token lives for weeks-months and is a full master credential for the
  account - treat aas_token like a password (0600, never commit).
- oauth_token is single-use: if exchange_token answers BadAuthentication right after
  a successful flow, the cookie was already consumed - rerun mint_aas.py.
- Play serves staged rollouts per account+device cohort: `pull.py check` tells you
  what YOUR cohort currently gets, which may lag the newest release by days.
- The reference emulator is only needed again if you want to observe GMS internals
  (checkin protobufs, device-key registration); plain pulls don't touch it.
