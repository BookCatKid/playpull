#!/usr/bin/env python3
"""playpull - pure-python Google Play APK puller. No emulator, no physical device.

Commands:
  init            Register a fresh device identity to the account (one-time; writes
                  gsf_id + tokens into config.json). Requires aas_token (run mint_aas.py first).
  check           Print the version Play would serve this account/device cohort.
  pull PREFIX     If the served version starts with PREFIX: purchase, download all
                  splits, verify package name + version + signing certificate.
  selfcheck       Stage-by-stage health check with remedies for each failure.
  checkin         Re-checkin with the stored device id (keeps the registration alive
                  if you run pull.py rarely; check/pull do this automatically once a day).

Secrets: config.json (gitignored) holds email + device ids; aas_token (gitignored, chmod 600)
holds the master token. Neither is ever printed. See README.md for the full flow.
"""
import sys, os, json, time
from loguru import logger as _loguru_logger
_loguru_logger.remove()  # silence androguard's debug flood
import requests
import gpsoauth
from gpapi.googleplay import GooglePlayAPI
from gpapi.config import DeviceBuilder
from gpapi import googleplay_pb2

DIR = os.path.dirname(os.path.abspath(__file__))
CHECKIN_URL = 'https://android.clients.google.com/checkin'
FDFE = 'https://android.clients.google.com/fdfe/'
PLAY_SCOPE = 'oauth2:https://www.googleapis.com/auth/googleplay'
PLAY_APP = 'com.android.vending'
# GMS/Play client signature (public constant, the same one gpsoauth documents)
CLIENT_SIG = '38918a453d07199354f8b19af05ec6562ced5788'
CHECKIN_REFRESH_SECS = 24 * 3600

class PullError(Exception):
    """stage: which pipeline stage failed; remedy: what the user should run."""
    def __init__(self, stage, msg, remedy=None):
        super().__init__(msg); self.stage = stage; self.remedy = remedy

def die(e):
    print('ERROR [%s] %s' % (e.stage, e), file=sys.stderr)
    if e.remedy: print('  fix: %s' % e.remedy, file=sys.stderr)
    sys.exit(1)

def load_config(require_device=True):
    try:
        cfg = json.load(open(os.path.join(DIR, 'config.json')))
    except FileNotFoundError:
        raise PullError('config', 'config.json not found (copy config.example.json and fill it in)',
                        'cp config.example.json config.json && edit config.json')
    except json.JSONDecodeError as e:
        raise PullError('config', 'config.json is not valid JSON: %s' % e)
    if not cfg.get('email'):
        raise PullError('config', 'config.json has no email')
    if require_device and not cfg.get('gsf_id'):
        raise PullError('device', 'no device registered yet (config.json has no gsf_id)',
                        'python3 pull.py init')
    return cfg

def save_config(cfg):
    p = os.path.join(DIR, 'config.json')
    json.dump(cfg, open(p, 'w'), indent=2, sort_keys=True)
    os.chmod(p, 0o600)

def load_aas():
    try:
        return open(os.path.join(DIR, 'aas_token')).read().strip()
    except FileNotFoundError:
        raise PullError('auth', 'aas_token not found - no master token minted yet',
                        'python3 mint_aas.py')

def oauth(email, aas, android_id, service, app, sdk=29):
    try:
        r = gpsoauth.perform_oauth(email, aas, android_id, service=service, app=app,
            client_sig=CLIENT_SIG, device_country='us', operator_country='us',
            lang='en', sdk_version=sdk)
    except requests.RequestException as e:
        raise PullError('network', 'auth request failed: %s' % e, 'check connectivity, retry')
    if 'Error' in r:
        if r['Error'] in ('BadAuthentication', 'NeedsBrowser', 'DeletedGmail'):
            raise PullError('auth', 'AAS token rejected (%s) - it expired or was revoked' % r['Error'],
                            'python3 mint_aas.py  (needs the account password + one 2SV code)')
        raise PullError('auth', 'token mint failed: %s' % r)
    return r['Auth']

def post_with_retry(url, headers, data=None, params=None, tries=3, stage='network'):
    last = None
    for i in range(tries):
        try:
            r = requests.post(url, headers=headers, data=data, params=params, timeout=60)
            if r.status_code < 500:
                return r
            last = PullError(stage, 'server %s from %s' % (r.status_code, url.rsplit('/',1)[-1]))
        except requests.RequestException as e:
            last = PullError(stage, '%s' % e, 'transient network failure - retry')
        time.sleep(1.5 * (i + 1))
    raise last

def get_with_retry(url, headers, params=None, tries=3, stage='network'):
    last = None
    for i in range(tries):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=60)
            if r.status_code < 500:
                return r
            last = PullError(stage, 'server %s from %s' % (r.status_code, url.rsplit('/',1)[-1]))
        except requests.RequestException as e:
            last = PullError(stage, '%s' % e, 'transient network failure - retry')
        time.sleep(1.5 * (i + 1))
    raise last

def make_builder(cfg):
    b = DeviceBuilder('bacon')  # complete base field set; overridden below
    b.locale = 'en_US'; b.timezone = 'PST8PDT'
    dev = dict(cfg['device'])
    dev['vending.version'] = cfg['finsky']['version']
    dev['vending.versionstring'] = cfg['finsky']['versionstring']
    b.device.update(dev)
    return b

def do_checkin(cfg, builder, email, ac2dm, android_id=0, security_token=0, bind_account=False):
    """One checkin POST. Returns parsed AndroidCheckinResponse."""
    req = builder.getAndroidCheckinRequest()
    req.checkin.build.timestamp = int(time.time() * 1000)
    req.id = android_id
    if security_token:
        req.securityToken = security_token
    if bind_account:
        req.accountCookie.append('[' + email + ']')
        req.accountCookie.append(ac2dm)
    h = dict(builder.getAuthHeaders(None))
    h['Content-Type'] = 'application/x-protobuffer'   # mandatory; missing = HTTP 400
    r = post_with_retry(CHECKIN_URL, h, data=req.SerializeToString(), stage='checkin')
    resp = googleplay_pb2.AndroidCheckinResponse()
    try:
        resp.ParseFromString(r.content)
    except Exception:
        raise PullError('checkin', 'unparseable checkin response (http %s)' % r.status_code)
    return resp

def cmd_init(cfg):
    """Register a fresh device identity: anonymous checkin -> account-bound checkin ->
    uploadDeviceConfig. Writes gsf_id + security_token into config.json."""
    if cfg.get('gsf_id'):
        raise PullError('device', 'a device is already registered (gsf_id present); '
                        'edit config.json to remove it if you really want a new one')
    email = cfg['email']; aas = load_aas()
    b = make_builder(cfg)
    ac2dm = oauth(email, aas, '0', service='ac2dm', app='com.google.android.gms')
    c1 = do_checkin(cfg, b, email, ac2dm)
    if not c1.androidId:
        raise PullError('checkin', 'server returned no androidId (registration rejected)')
    do_checkin(cfg, b, email, ac2dm, android_id=c1.androidId,
               security_token=c1.securityToken, bind_account=True)
    cfg['gsf_id'] = str(c1.androidId)
    cfg['security_token'] = str(c1.securityToken)
    cfg['consistency_token'] = c1.deviceCheckinConsistencyToken or ''
    cfg['digest'] = c1.digest or ''
    cfg['last_checkin'] = int(time.time())
    save_config(cfg)
    api = build_api(cfg)
    api.uploadDeviceConfig()
    print('registered device gsf_id=%s, config uploaded' % c1.androidId)

def maybe_refresh_checkin(cfg):
    """Re-checkin if stale (>24h), keeping the server-side record alive. Best-effort:
    a failed refresh never breaks a pull."""
    if time.time() - cfg.get('last_checkin', 0) < CHECKIN_REFRESH_SECS:
        return
    try:
        email = cfg['email']; aas = load_aas()
        b = make_builder(cfg)
        ac2dm = oauth(email, aas, cfg['gsf_id'], service='ac2dm', app='com.google.android.gms')
        do_checkin(cfg, b, email, ac2dm, android_id=int(cfg['gsf_id']),
                   security_token=int(cfg.get('security_token') or 0), bind_account=True)
        cfg['last_checkin'] = int(time.time())
        save_config(cfg)
    except PullError:
        pass  # stale registration is still usable; next success refreshes it

def build_api(cfg):
    email = cfg['email']; aas = load_aas()
    tok = oauth(email, aas, cfg['gsf_id'], service=PLAY_SCOPE, app=PLAY_APP)
    b = make_builder(cfg)
    api = GooglePlayAPI('en_US', 'PST8PDT'); api.deviceBuilder = b
    api.gsfId = int(cfg['gsf_id'])
    api.setAuthSubToken(tok)
    return api

def fdfe_headers(api):
    return api.getHeaders()

def parse_wrapper(resp):
    return googleplay_pb2.ResponseWrapper.FromString(resp.content)

def served_version(api, pkg):
    r = get_with_retry(FDFE + 'details', fdfe_headers(api), params={'doc': pkg}, stage='fdfe')
    msg = parse_wrapper(r)
    err = msg.commands.displayErrorMessage
    if r.status_code == 400 and 'DF-DFERH-01' in err:
        raise PullError('device', 'device id rejected (DF-DFERH-01) - registration lost or header invalid',
                        'remove gsf_id/security_token from config.json, then: python3 pull.py init')
    try:
        det = msg.payload.detailsResponse.docV2.details.appDetails
        return det.versionString, det.versionCode
    except AttributeError:
        raise PullError('fdfe', 'no details for %s (http %s, err=%s). The store returned an '
                        'empty catalog for this device id - registration may be incomplete'
                        % (pkg, r.status_code, err or 'none'),
                        'python3 pull.py selfcheck')

def cmd_check(cfg, pkg):
    api = build_api(cfg)
    maybe_refresh_checkin(cfg)
    vs, vc = served_version(api, pkg)
    print('served: %s (vc %s)' % (vs, vc))
    return vs, vc

def cmd_pull(cfg, pkg, want):
    api = build_api(cfg)
    maybe_refresh_checkin(cfg)
    vs, vc = served_version(api, pkg)
    print('served: %s (vc %s)' % (vs, vc))
    if want and not vs.startswith(want):
        print('prefix %s not in served version - not pulling' % want); sys.exit(2)
    h = fdfe_headers(api); h['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    pr = post_with_retry(FDFE + 'purchase', h, data={'ot': '1', 'doc': pkg, 'vc': str(vc)}, stage='fdfe')
    br = parse_wrapper(pr).payload.buyResponse
    if not br.downloadToken:
        raise PullError('fdfe', 'purchase returned no download token (err=%s)'
                        % (parse_wrapper(pr).commands.displayErrorMessage or 'none'))
    dl = get_with_retry(FDFE + 'delivery', h, params={'doc': pkg, 'vc': str(vc), 'ot': '1',
                        'dtok': br.downloadToken}, stage='fdfe')
    dmsg = parse_wrapper(dl)
    dd = dmsg.payload.deliveryResponse.appDeliveryData
    if not dd.downloadUrl:
        raise PullError('fdfe', 'delivery returned no URL (err=%s)'
                        % (dmsg.commands.displayErrorMessage or 'none'))
    cookie = '; '.join('%s=%s' % (c.name, c.value) for c in dd.downloadAuthCookie)
    targets = [('base.apk', dd.downloadUrl)] + [('split_%s.apk' % s.name, s.downloadUrl) for s in dd.split]
    for name, url in targets:
        for attempt in range(3):
            r = requests.get(url, headers={'Cookie': cookie}, timeout=600)
            if r.status_code == 200:
                break
            time.sleep(2 * (attempt + 1))
        else:
            raise PullError('network', 'download of %s failed (http %s)' % (name, r.status_code), 'retry')
        open(os.path.join(DIR, name), 'wb').write(r.content)
        print('downloaded %s %d bytes' % (name, len(r.content)))
    verify(cfg, pkg, want)

def verify(cfg, pkg, want):
    from androguard.core.apk import APK
    a = APK(os.path.join(DIR, 'base.apk'))
    certs = list(a.get_certificates())
    sha256 = certs[0].sha256_fingerprint.replace(' ', '').upper() if certs else ''
    expect = (cfg.get('cert_sha256') or '').upper()
    checks = [('package', a.get_package() == pkg, a.get_package()),
              ('version', (not want) or a.get_androidversion_name().startswith(want), a.get_androidversion_name()),
              ('signer', (not expect) or sha256 == expect, sha256[:16] + '...')]
    bad = [c for c in checks if not c[1]]
    for name, ok, got in checks:
        print('verify %-8s %s (%s)' % (name, 'OK' if ok else 'MISMATCH', got))
    if bad:
        raise PullError('verify', 'APK failed verification: %s' % ', '.join(c[0] for c in bad),
                        'do NOT use these files; the source is not who it claims to be')
    print('GENUINE - signature matches the expected release certificate')

def cmd_selfcheck(cfg_path_hint=None):
    print('playpull selfcheck')
    ok = True
    try:
        cfg = load_config(require_device=False)
        print('  [ok] config.json parses; email set')
    except PullError as e:
        print('  [FAIL] config: %s\n         fix: %s' % (e, e.remedy)); sys.exit(1)
    try:
        load_aas()
        print('  [ok] aas_token present')
    except PullError as e:
        print('  [FAIL] auth: %s\n         fix: %s' % (e, e.remedy)); sys.exit(1)
    try:
        oauth(cfg['email'], load_aas(), cfg.get('gsf_id') or '0', service=PLAY_SCOPE, app=PLAY_APP)
        print('  [ok] AAS token accepted (scope token minted)')
    except PullError as e:
        print('  [FAIL] auth: %s\n         fix: %s' % (e, e.remedy)); sys.exit(1)
    if not cfg.get('gsf_id'):
        print('  [FAIL] device: not registered\n         fix: python3 pull.py init'); sys.exit(1)
    print('  [ok] device registered (gsf_id present)')
    try:
        cmd_check(cfg, cfg.get('package', 'com.sonos.acr2'))
        print('  [ok] FDFE details works - pipeline healthy')
    except PullError as e:
        print('  [FAIL] fdfe: %s\n         fix: %s' % (e, e.remedy)); sys.exit(1)
    print('all checks passed')

USAGE = __doc__
if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'check'
    try:
        if cmd == 'init':
            cmd_init(load_config(require_device=False))
        elif cmd == 'check':
            cmd_check(load_config(), load_config().get('package', 'com.sonos.acr2'))
        elif cmd == 'pull':
            if len(sys.argv) < 3:
                print('usage: pull.py pull VERSION_PREFIX'); sys.exit(2)
            cfg = load_config()
            cmd_pull(cfg, cfg.get('package', 'com.sonos.acr2'), sys.argv[2])
        elif cmd == 'selfcheck':
            cmd_selfcheck()
        elif cmd == 'checkin':
            cfg = load_config()
            cfg['last_checkin'] = 0
            maybe_refresh_checkin(cfg)
            print('checkin refreshed')
        else:
            print(USAGE)
    except PullError as e:
        die(e)
