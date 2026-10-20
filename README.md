# playpull - pure-python Google Play APK puller

Downloads APKs straight from Google Play exactly as a signed-in Android device would:
a real account sign-in, a real device registration (checkin), and the same FDFE
endpoints the Play Store app uses. No emulator, no physical device, no third-party
mirrors. Works for any free app.

## Quickstart

```
pip install gpsoauth googleplay-api androguard cryptography playwright requests
python3 -m playwright install chromium
cp config.example.json config.json   # fill in email; leave the rest as shipped

xvfb-run -a python3 mint_aas.py                 # one-time: browser sign-in (password + 2SV)
python3 pull.py init                            # one-time: register a fresh device identity
python3 pull.py check com.google.android.calculator
python3 pull.py pull com.google.android.calculator            # TOFU: prints the signer
python3 pull.py pull com.google.android.calculator 9.3 --pin-sha256 <sha256 from the TOFU print>
python3 pull.py selfcheck                       # stage-by-stage health check
```

Downloads land in `./<package>/v<versionCode>/` (base.apk + split_*.apk), promoted
there in one atomic rename after all checks pass; `./<package>/current` is a symlink
to the latest version. A re-pull of an already-pulled version keeps the existing files.

## Trust model

Every downloaded file is verified before it reaches `./<package>/v<versionCode>/`:

- the sha256 of each file is checked against the hash Play's delivery response
  carries for it. Play sometimes omits the hash for a file: a loud warning is
  printed per file (set `strict_hashes: true` in config.json to fail instead);
- each split's APK Signature Scheme v2/v3 block is cryptographically verified in
  pure python, mirroring Android's apksig: signature over the signed data plus the
  content digest over the whole file, EOCD must end exactly at EOF, zip comments
  are covered by the digest, the signatures/digests algorithm lists must match,
  v3 inner/outer SDK ranges must agree, and v3 is preferred over v2. A modified,
  truncated, or appended-to APK fails; v1-only files are rejected. Cross-checked
  against the reference apksigner on crafted fixtures. v3.1-only files (key
  rotation lineage) are refused; files carrying v3.1 alongside v3/v2 verify via
  the v3/v2 block, so on key-rotated apps the reported signer is the pre-rotation
  certificate (stable across pulls); a stripped scheme block is detected via the
  stripping-protection attribute;
- all splits must be signed by the SAME certificate;
- the base APK's package name must equal the request and its versionCode must
  equal the versionCode Play said it would serve;
- downloads stage into a scratch dir inside the package dir and are promoted to
  the immutable `./<package>/v<versionCode>/` in ONE atomic rename after every
  check passes, so a failed pull can never leave a mix of old and new files or
  clobber a previously verified set.

On top of that you choose per app:

- `--pin-sha256 HEX` requires an exact signer match; the pin is saved in config.json
  and enforced on later pulls without the flag. A mismatch aborts with a loud error.
- Without a pin the signature is still verified, but the signer is reported as
  UNVERIFIED (TOFU): a valid signature only proves the file matches its own
  certificate, not that the certificate is the developer's. Pin it after checking
  the fingerprint out-of-band.

This catches the classic mirror trap: aggregator sites sometimes serve re-signed
installer stubs under the real app's name. A genuine Play download verifies against
the developer's certificate; a re-signed stub does not.

## How it works (reproduced from an actual device)

1. **Sign-in** (`mint_aas.py`): drives accounts.google.com/EmbeddedSetup in full
   chromium (headless is rejected as "insecure"; use xvfb on a headless box).
   Email -> password -> 2SV -> "I agree". On completion Google sets an HttpOnly
   `oauth_token` cookie, **single-use**, which is exchanged for an **AAS master
   token** (`aas_et/...`, written to `aas_token`, chmod 600). This mirrors what GMS
   does on-device; raw password auth on android.clients.google.com/auth is dead
   (BadAuthentication regardless of device trust).
2. **Device registration** (`pull.py init`): mints an `ac2dm` token from the AAS,
   then performs the two-step GMS checkin (anonymous -> account-bound) and uploads
   the device config. Result: a fresh GSF android_id registered to the account,
   stored in config.json. Gotcha that cost an hour: the checkin POST needs
   `Content-Type: application/x-protobuffer` or the server answers HTTP 400.
3. **Pulling** (`check`/`pull`): exchanges the AAS for a token scoped
   `oauth2:https://www.googleapis.com/auth/googleplay` (app com.android.vending),
   then FDFE `details` -> `acquire` -> `purchase` -> `delivery` -> download of
   every split -> verification. The `acquire` step (protobuf POST) is the modern
   first-time-acquisition ceremony: without it, the plain form-encoded `purchase`
   is rejected with DF-DFERH-01 for never-owned apps in some categories (measured
   on Mature 17+ titles); already-owned apps skip it. Paid apps are refused
   before any purchase call.

## What actually matters (measured, Oct 2026)

Required: a valid AAS token; the googleplay-scope token (legacy `service=android`
gives 401 DF-DFERH-01); a registered GSF id in the `X-DFE-Device-Id` header (absent
gives 400; an unknown id gives a silently empty store).

NOT required (each verified by removing it): the Finsky User-Agent version (a 2017
"Android-Finsky/8.4.19" works; even a fake "99.0.0" works), any specific device
profile fields (a 2015 OnePlus One profile works), uploadDeviceConfig for pulls,
Play Integrity / attestation (fails on our reference device; everything works anyway).
UA and profile stay current in config.json as cheap insurance; bump
`finsky.versionstring`/`version` there if Google ever starts enforcing again.

## Maintenance (what breaks and how to fix it)

| Symptom | Cause | Fix |
| --- | --- | --- |
| `auth: AAS token rejected (BadAuthentication)` | token revoked: password/2SV change, "sign out all devices", security lockdown, manual revocation at myaccount.google.com/permissions | `xvfb-run -a python3 mint_aas.py` (one 2SV code) |
| `device: device id rejected (DF-DFERH-01)` or empty catalog | registration pruned after long inactivity | remove gsf_id/security_token from config.json, then `python3 pull.py init` |
| `fdfe: server 5xx` / network errors | transient | automatic retries (3x backoff); just rerun |
| `no details for ...` / `Item not found` | package typo, delisted app, region lock, device filter (sdk too old), or the staged rollout has not reached this cohort | check the id; cohorts lag, retry later |
| purchase `DF-DFERH-01` on a specific app while others pull fine | genuine server-side refusal (the acquire ceremony already ran): developer acquisition restriction, region, or account standing | try the app in the real Play Store on the same account; whatever error it shows is the answer |
| everything else stale | Google bumped minimum client | bump `finsky.*` in config.json |

`check`/`pull` auto-refresh the checkin once a day, keeping the registration alive.
`selfcheck` diagnoses in order: config -> token file -> AAS validity -> device
registration -> live FDFE call, printing the exact remedy for the failed stage.

## Tests

`python3 tests/run_fixtures.py` - offline fixture-matrix test for the signature
verifier (11 crafted APKs, expected accept/reject matches the reference
apksigner). See tests/README.md.

## Notes

- The served version depends on the account+device cohort (staged rollouts).
  `check` tells you what YOUR cohort gets, which can lag the newest release by days.
- aas_token is a full master credential for the account. chmod 600, never commit.
  Use a throwaway account: automated access is outside Play's ToS, so do not risk
  an account you care about.
