# playpull - pure-python Google Play APK puller

Downloads APKs straight from Google Play exactly as a signed-in Android device would.
No emulator, no physical device, no third-party mirrors: a real account sign-in, a real
device registration (checkin), and the same FDFE endpoints the Play Store app uses.

## Quickstart

```
pip install gpsoauth googleplay-api androguard playwright requests
python3 -m playwright install chromium
cp config.example.json config.json   # fill in email; leave the rest as shipped

xvfb-run -a python3 mint_aas.py      # one-time: browser sign-in (password + 2SV) -> aas_token
python3 pull.py init                 # one-time: register a fresh device identity -> config.json
python3 pull.py check                # what version would Play serve this account/device?
python3 pull.py pull 90.01           # purchase + download + verify all splits
python3 pull.py selfcheck            # stage-by-stage health check with remedies
```

## How it works (reproduced from an actual device)

1. **Sign-in** (`mint_aas.py`): drives accounts.google.com/EmbeddedSetup in full
   chromium (headless is rejected as "insecure"; use xvfb on a headless box).
   Email -> password -> 2SV -> "I agree". On completion Google sets an HttpOnly
   `oauth_token` cookie - **single-use** - which is exchanged for an **AAS master
   token** (`aas_et/...`, written to `aas_token`, chmod 600). This mirrors what GMS
   does on-device; raw password auth on android.clients.google.com/auth is dead
   (BadAuthentication regardless of device trust).
2. **Device registration** (`pull.py init`): mints an `ac2dm` token from the AAS,
   then performs the two-step GMS checkin (anonymous -> account-bound) with a
   Pixel-7 profile, and uploads the device config. Result: a fresh GSF android_id
   registered to the account, stored in config.json. No emulator involved.
   Gotcha that cost an hour: the checkin POST needs `Content-Type:
   application/x-protobuffer` or the server answers HTTP 400.
3. **Pulling** (`pull.py check|pull`): exchanges the AAS for a token scoped
   `oauth2:https://www.googleapis.com/auth/googleplay` (app com.android.vending),
   then calls FDFE `details` -> `purchase` (free acquire) -> `delivery`, and
   downloads every split. The APK is verified: package name, version, and signer
   certificate must match `cert_sha256` in config.json or the files are rejected.

## What actually matters (measured, Oct 2026)

Required: a valid AAS token; the googleplay-scope token (legacy `service=android`
-> 401 DF-DFERH-01); a registered GSF id in the `X-DFE-Device-Id` header (absent ->
400; unknown id -> silently empty store).

NOT required (each verified by removing it): the Finsky User-Agent version (a 2017
"Android-Finsky/8.4.19" works; even a fake "99.0.0" works), any specific device
profile fields (a 2015 OnePlus One profile works), uploadDeviceConfig for pulls,
Play Integrity / attestation (fails on our reference device; everything works anyway).
The UA and profile are still kept current in config.json as cheap insurance - bump
`finsky.versionstring`/`version` there if Google ever starts enforcing again.

## Maintenance (what breaks and how to fix it)

| Symptom | Cause | Fix |
| --- | --- | --- |
| `auth: AAS token rejected (BadAuthentication)` | token revoked: password/2SV change, "sign out all devices", security lockdown, manual revocation at myaccount.google.com/permissions | `xvfb-run -a python3 mint_aas.py` (one 2SV code) |
| `device: device id rejected (DF-DFERH-01)` or empty catalog | registration pruned after long inactivity | remove gsf_id/security_token from config.json, `python3 pull.py init` |
| `fdfe: server 5xx` / network errors | transient | automatic retries (3x backoff); just rerun |
| everything else stale | Google bumped minimum client | bump `finsky.*` in config.json |

`check`/`pull` auto-refresh the checkin once a day, which keeps the registration
alive. `selfcheck` diagnoses in order: config -> token file -> AAS validity ->
device registration -> live FDFE call, printing the exact remedy for the failed stage.

## Notes

- The served version depends on the account+device cohort (staged rollouts).
  `check` tells you what YOUR cohort gets, which can lag the newest release.
- aas_token is a full master credential for the account. chmod 600, never commit,
  use a throwaway account - automated access is outside Play's ToS, so don't risk
  an account you care about.
- Sonos's current release cert: sha256
  7C34EB3CFBDA05FAF56E8890A2ABBAC14B3036E6E4358849B98E8819B6B7B329
  (sha1 ae8894da0d05c79ba62c88ece076e86d779d800e). Aggregator mirrors sometimes
  serve re-signed installer stubs - always verify before trusting a mirror.
