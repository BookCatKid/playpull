#!/usr/bin/env python3
"""playpull - pure-python Google Play APK puller. No emulator, no physical device.

Commands:
  init                         Register a fresh device identity to the account (one-time;
                               writes gsf_id + tokens into config.json). Requires aas_token
                               (run mint_aas.py first).
  check PACKAGE                Print the version Play would serve this account/device cohort.
  pull PACKAGE [PREFIX]        Purchase (free apps only), download all splits, verify.
                               PREFIX: only proceed if the served version starts with it.
                               --pin-sha256 HEX: require this signer certificate (saved to
                               config for next time). Without a pin the actual signer is
                               printed (trust on first use: re-run with --pin-sha256 to pin).
  selfcheck                    Stage-by-stage health check with remedies for each failure.
  checkin                      Re-checkin with the stored device id (check/pull do this
                               automatically once a day).

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

def _req(method, url, headers, data=None, params=None, tries=3, stage='network'):
    last = None
    for i in range(tries):
        try:
            r = requests.request(method, url, headers=headers, data=data, params=params, timeout=60)
            if r.status_code < 500:
                return r
            last = PullError(stage, 'server %s from %s' % (r.status_code, url.rsplit('/', 1)[-1]))
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
    r = _req('POST', CHECKIN_URL, h, data=req.SerializeToString(), stage='checkin')
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

def parse_wrapper(resp):
    return googleplay_pb2.ResponseWrapper.FromString(resp.content)

def get_details(api, pkg):
    r = _req('GET', FDFE + 'details', api.getHeaders(), params={'doc': pkg}, stage='fdfe')
    msg = parse_wrapper(r)
    err = msg.commands.displayErrorMessage
    if r.status_code == 400 and 'DF-DFERH-01' in err:
        raise PullError('device', 'device id rejected (DF-DFERH-01) - registration lost or header invalid',
                        'remove gsf_id/security_token from config.json, then: python3 pull.py init')
    try:
        doc = msg.payload.detailsResponse.docV2
        det = doc.details.appDetails
        if not det.versionString or not det.versionCode:
            raise AttributeError('empty appDetails')
        return doc, det.versionString, det.versionCode
    except AttributeError:
        raise PullError('fdfe', 'no details for %s (http %s, err=%s). Not served to this '
                        'device/account cohort, or the package does not exist'
                        % (pkg, r.status_code, err or 'none'),
                        'check the package id; staged rollouts also lag by cohort')

def offer_price(doc):
    """(micros, currency) of the first offer; (0, '') when free or unknown."""
    try:
        o = doc.offer[0]
        return o.micros, o.currencyCode
    except Exception:
        return 0, ''

def cmd_check(cfg, pkg):
    api = build_api(cfg)
    maybe_refresh_checkin(cfg)
    _, vs, vc = get_details(api, pkg)
    print('served: %s (vc %s)' % (vs, vc))
    return vs, vc

def cmd_pull(cfg, pkg, want, pin_arg):
    api = build_api(cfg)
    maybe_refresh_checkin(cfg)
    doc, vs, vc = get_details(api, pkg)
    print('served: %s (vc %s)' % (vs, vc))
    if want and not vs.startswith(want):
        print('prefix %s not in served version - not pulling' % want); sys.exit(2)
    micros, currency = offer_price(doc)
    if micros:
        raise PullError('fdfe', '%s is a paid app (%s %.2f). playpull only acquires free apps - '
                        'no purchase made' % (pkg, currency or '', micros / 1e6))
    h = api.getHeaders(); h['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    pr = _req('POST', FDFE + 'purchase', h, data={'ot': '1', 'doc': pkg, 'vc': str(vc)}, stage='fdfe')
    pmsg = parse_wrapper(pr)
    br = pmsg.payload.buyResponse
    if not br.downloadToken:
        err = pmsg.commands.displayErrorMessage or 'none'
        hint = ''
        if 'DF-DFERH-01' in err:
            hint = (' For a specific app (while others pull fine) this usually means the account '
                    'is not eligible for it - typical causes: age-restricted rating (17+/18+) on an '
                    'account without verified age, or a developer-side acquisition restriction.')
        raise PullError('fdfe', 'purchase returned no download token (err=%s).%s' % (err, hint))
    dl = _req('GET', FDFE + 'delivery', h, params={'doc': pkg, 'vc': str(vc), 'ot': '1',
              'dtok': br.downloadToken}, stage='fdfe')
    dmsg = parse_wrapper(dl)
    dd = dmsg.payload.deliveryResponse.appDeliveryData
    if not dd.downloadUrl:
        raise PullError('fdfe', 'delivery returned no URL (err=%s)'
                        % (dmsg.commands.displayErrorMessage or 'none'))
    cookie = '; '.join('%s=%s' % (c.name, c.value) for c in dd.downloadAuthCookie)
    targets = [('base.apk', dd.downloadUrl)] + [('split_%s.apk' % s.name, s.downloadUrl) for s in dd.split]
    outdir = os.path.join(DIR, pkg)
    os.makedirs(outdir, exist_ok=True)
    for name, url in targets:
        for attempt in range(3):
            r = requests.get(url, headers={'Cookie': cookie}, timeout=600)
            if r.status_code == 200:
                break
            time.sleep(2 * (attempt + 1))
        else:
            raise PullError('network', 'download of %s failed (http %s)' % (name, r.status_code), 'retry')
        open(os.path.join(outdir, name), 'wb').write(r.content)
        print('downloaded %s/%s %d bytes' % (pkg, name, len(r.content)))
    verify(cfg, pkg, want, pin_arg, outdir)

def signer_info(apk_path):
    from androguard.core.apk import APK
    a = APK(apk_path)
    certs = list(a.get_certificates())
    sha256 = certs[0].sha256_fingerprint.replace(' ', '').upper() if certs else ''
    subj = ''
    try:
        subj = certs[0].subject.human_friendly
    except AttributeError:
        try:
            subj = certs[0].subject.rfc4514_string()
        except Exception:
            subj = '?'
    return a, sha256, subj

def verify(cfg, pkg, want, pin_arg, outdir):
    a, sha256, subj = signer_info(os.path.join(outdir, 'base.apk'))
    pin = (pin_arg or (cfg.get('pins') or {}).get(pkg) or '').upper()
    if a.get_package() != pkg:
        raise PullError('verify', 'package mismatch: got %s, wanted %s - do NOT use these files'
                        % (a.get_package(), pkg))
    print('verify package  OK (%s)' % pkg)
    if want and not a.get_androidversion_name().startswith(want):
        raise PullError('verify', 'version mismatch: got %s, wanted prefix %s'
                        % (a.get_androidversion_name(), want))
    print('verify version  OK (%s)' % a.get_androidversion_name())
    print('signer sha256   %s' % sha256)
    print('signer subject  %s' % subj)
    if pin:
        if sha256 != pin:
            raise PullError('verify', 'SIGNER MISMATCH: got %s, pinned %s - do NOT use these files'
                            % (sha256[:16] + '...', pin[:16] + '...'))
        if pin_arg:
            cfg.setdefault('pins', {})[pkg] = pin
            save_config(cfg)
        print('verify signer   OK (matches pinned certificate)')
    else:
        print('verify signer   UNPINNED - first observation, nothing to compare against.')
        print('                If you trust this signer, pin it: python3 pull.py pull %s %s '
              '--pin-sha256 %s' % (pkg, want or '', sha256))

def cmd_selfcheck():
    print('playpull selfcheck')
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
        api = build_api(cfg)
        get_details(api, 'com.android.vending')
        print('  [ok] FDFE details works - pipeline healthy')
    except PullError as e:
        print('  [FAIL] fdfe: %s\n         fix: %s' % (e, e.remedy)); sys.exit(1)
    print('all checks passed')

USAGE = __doc__
if __name__ == '__main__':
    argv = sys.argv[1:]
    pin = None
    if '--pin-sha256' in argv:
        i = argv.index('--pin-sha256')
        try:
            pin = argv[i + 1]
        except IndexError:
            print('--pin-sha256 needs a hex value'); sys.exit(2)
        del argv[i:i + 2]
    cmd = argv[0] if argv else 'check'
    try:
        if cmd == 'init':
            cmd_init(load_config(require_device=False))
        elif cmd == 'check':
            if len(argv) < 2:
                print('usage: pull.py check PACKAGE'); sys.exit(2)
            cmd_check(load_config(), argv[1])
        elif cmd == 'pull':
            if len(argv) < 2:
                print('usage: pull.py pull PACKAGE [VERSION_PREFIX] [--pin-sha256 HEX]'); sys.exit(2)
            cmd_pull(load_config(), argv[1], argv[2] if len(argv) > 2 else '', pin)
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
