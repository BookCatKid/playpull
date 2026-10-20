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
import sys, os, json, time, hashlib, struct, shutil
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

def _req(method, url, headers, data=None, params=None, tries=3, stage='network', allow=()):
    """Retries on 5xx/network errors. 4xx is a loud failure unless listed in allow -
    a client error must never silently flow into a later parse."""
    last = None
    for i in range(tries):
        try:
            r = requests.request(method, url, headers=headers, data=data, params=params, timeout=60)
            if r.status_code < 500:
                if r.status_code >= 400 and r.status_code not in allow:
                    raise PullError(stage, 'http %s from %s: %s'
                                    % (r.status_code, url.rsplit('/', 1)[-1], r.text[:300]))
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

def refresh_checkin(cfg):
    """One account-bound re-checkin. Raises PullError on failure."""
    email = cfg['email']; aas = load_aas()
    b = make_builder(cfg)
    ac2dm = oauth(email, aas, cfg['gsf_id'], service='ac2dm', app='com.google.android.gms')
    do_checkin(cfg, b, email, ac2dm, android_id=int(cfg['gsf_id']),
               security_token=int(cfg.get('security_token') or 0), bind_account=True)
    cfg['last_checkin'] = int(time.time())
    save_config(cfg)

def maybe_refresh_checkin(cfg):
    """Re-checkin if stale (>24h), keeping the server-side record alive. Best-effort:
    a failed refresh never breaks a pull - but it is printed, not hidden."""
    if time.time() - cfg.get('last_checkin', 0) < CHECKIN_REFRESH_SECS:
        return
    try:
        refresh_checkin(cfg)
    except PullError as e:
        print('warning: checkin refresh failed (%s) - continuing with stale registration' % e)

def build_api(cfg):
    email = cfg['email']; aas = load_aas()
    tok = oauth(email, aas, cfg['gsf_id'], service=PLAY_SCOPE, app=PLAY_APP)
    b = make_builder(cfg)
    api = GooglePlayAPI('en_US', 'PST8PDT'); api.deviceBuilder = b
    api.gsfId = int(cfg['gsf_id'])
    api.setAuthSubToken(tok)
    return api

def _varint(n):
    out = b''
    while True:
        b = n & 0x7F; n >>= 7
        out += bytes([b | 0x80]) if n else bytes([b])
        if not n:
            return out

def _field_varint(num, val):
    return _varint(num << 3) + _varint(val)

def _field_msg(num, body):
    return _varint(num << 3 | 2) + _varint(len(body)) + body

def build_acquire_request(pkg, vc, ot=1):
    """Modern first-time acquisition ceremony (POST /fdfe/acquire, protobuf).
    Layout mirrors what Finsky/Aurora send; field names per AcquireApp.proto."""
    import base64
    payload = _field_msg(1, pkg.encode()) + _field_varint(2, 1) + _field_varint(3, 3)
    package = _field_msg(1, payload) + _field_varint(2, 1)
    version = _field_varint(1, vc) + _field_varint(3, 0)
    m30 = _field_varint(1, 2) + _field_varint(2, 0)
    nonce = 'nonce=' + base64.urlsafe_b64encode(os.urandom(256)).decode().rstrip('=')
    return (_field_msg(1, package) + _field_msg(12, version) + _field_varint(13, ot) +
            _field_varint(15, 0) + _field_msg(22, nonce.encode()) + _field_varint(25, 2) +
            _field_msg(30, m30))

def acquire(api, pkg, vc, ot=1):
    """Best-effort first-time acquisition. Without this, the plain purchase call is
    rejected (DF-DFERH-01) for never-owned apps in some categories (measured on
    Mature 17+ titles); already-owned apps don't need it. The result is always
    printed - a failed acquire is not fatal on its own (owned apps skip it), but
    it must never be silent."""
    h = api.getHeaders()
    h['Content-Type'] = 'application/x-protobuf'
    try:
        r = requests.post(FDFE + 'acquire', headers=h, data=build_acquire_request(pkg, vc, ot), timeout=30)
    except requests.RequestException as e:
        print('acquire: request failed (%s) - continuing to purchase' % e)
        return False
    err = ''
    try:
        err = parse_wrapper(r).commands.displayErrorMessage or ''
    except Exception:
        pass
    if r.status_code != 200 or err:
        print('acquire: not accepted (http %s, err=%s) - continuing to purchase'
              % (r.status_code, err or 'none'))
        return False
    print('acquire: accepted')
    return True

def parse_wrapper(resp):
    return googleplay_pb2.ResponseWrapper.FromString(resp.content)

def get_details(api, pkg):
    r = _req('GET', FDFE + 'details', api.getHeaders(), params={'doc': pkg}, stage='fdfe', allow=(400,))
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
    acquire(api, pkg, vc)
    h = api.getHeaders(); h['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    pr = _req('POST', FDFE + 'purchase', h, data={'ot': '1', 'doc': pkg, 'vc': str(vc)}, stage='fdfe')
    pmsg = parse_wrapper(pr)
    br = pmsg.payload.buyResponse
    if not br.downloadToken:
        err = pmsg.commands.displayErrorMessage or 'none'
        hint = ''
        if 'DF-DFERH-01' in err:
            hint = (' The acquire ceremony already ran, so this is a genuine server-side refusal: '
                    'the account is not eligible for this app (developer acquisition restriction, '
                    'region, or account standing).')
        raise PullError('fdfe', 'purchase returned no download token (err=%s).%s' % (err, hint))
    dl = _req('GET', FDFE + 'delivery', h, params={'doc': pkg, 'vc': str(vc), 'ot': '1',
              'dtok': br.downloadToken}, stage='fdfe')
    dmsg = parse_wrapper(dl)
    dd = dmsg.payload.deliveryResponse.appDeliveryData
    if not dd.downloadUrl:
        raise PullError('fdfe', 'delivery returned no URL (err=%s)'
                        % (dmsg.commands.displayErrorMessage or 'none'))
    cookie = '; '.join('%s=%s' % (c.name, c.value) for c in dd.downloadAuthCookie)

    def _sha(x):
        """Server hashes arrive as base64 (sometimes raw bytes or hex) - normalize to hex."""
        import base64
        if isinstance(x, bytes):
            return x.hex()
        x = x or ''
        if len(x) == 64 and all(c in '0123456789abcdefABCDEF' for c in x):
            return x.lower()
        try:
            return base64.b64decode(x + '=' * (-len(x) % 4)).hex()
        except Exception:
            return 

    expect = {'base.apk': (dd.downloadUrl, _sha(dd.sha256))}
    for s in dd.split:
        expect['split_%s.apk' % s.name] = (s.downloadUrl, _sha(s.sha256))
    outdir = os.path.join(DIR, pkg)
    os.makedirs(outdir, exist_ok=True)
    # stage next to the final dir (same filesystem); the staged set is promoted
    # to the immutable version dir with ONE atomic rename after every check has
    # passed - a failed pull can never leave a mix of old and new files or
    # clobber a previously verified set.
    final = os.path.join(outdir, 'v%s' % vc)
    stage = os.path.join(outdir, '.staging-%s-%s' % (vc, os.getpid()))
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)
    strict_hashes = cfg.get('strict_hashes', False)
    for name, (url, want_sha) in expect.items():
        for attempt in range(3):
            r = requests.get(url, headers={'Cookie': cookie}, timeout=600)
            if r.status_code == 200:
                break
            time.sleep(2 * (attempt + 1))
        else:
            raise PullError('network', 'download of %s failed (http %s)' % (name, r.status_code), 'retry')
        digest = hashlib.sha256(r.content).hexdigest()
        if want_sha:
            if digest.lower() != want_sha.lower():
                raise PullError('verify', 'sha256 mismatch on %s: server said %s, got %s - '
                                'file discarded' % (name, want_sha[:16] + '...', digest[:16] + '...'))
            note = ' (matches server)'
        elif strict_hashes:
            raise PullError('verify', 'Play supplied no sha256 for %s - refusing the file '
                            '(strict_hashes is set)' % name)
        else:
            note = ' - WARNING: server supplied NO hash for this file, cannot cross-check'
            print('warning: Play supplied no sha256 for %s - skipping the hash cross-check' % name)
        part = os.path.join(stage, name + '.part')
        open(part, 'wb').write(r.content)
        os.replace(part, os.path.join(stage, name))
        print('downloaded %s/%s %d bytes sha256=%s%s' % (pkg, name, len(r.content),
              digest[:16] + '...', note))
    verify(cfg, pkg, want, pin_arg, stage, vc, sorted(expect))
    if os.path.isdir(final):
        shutil.rmtree(stage)
        print('v%s already pulled - staged copy discarded, existing files kept' % vc)
    else:
        os.replace(stage, final)  # one atomic rename: the set appears all at once
        print('promoted %d file(s) to %s/' % (len(expect), os.path.relpath(final, DIR)))
    # point the stable 'current' link at the newest version, atomically
    link_tmp = os.path.join(outdir, '.current.tmp')
    if os.path.lexists(link_tmp):
        os.remove(link_tmp)
    os.symlink('v%s' % vc, link_tmp)
    os.replace(link_tmp, os.path.join(outdir, 'current'))
    for old_f in os.listdir(outdir):
        if old_f.endswith('.apk'):  # pre-versioning layout leftovers
            os.remove(os.path.join(outdir, old_f))
    print('ready: %s' % os.path.join(os.path.relpath(outdir, DIR), 'current') + '/')

# ---- APK Signature Scheme v2/v3 verification (pure python) ----
# Mirrors Android's apksig (ApkSigningBlockUtils + V2/V3SchemeVerifier), not a
# guess from samples: EOCD must end exactly at EOF, the digested EOCD section
# includes the full comment, per-record length prefixes, ordered sig/digest
# algorithm-list equality, signer/signedData SDK range agreement (v3), and v3
# preferred over v2. Cross-checked against the reference apksigner jar.
from cryptography import x509 as _x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

_SIG_ALGOS = {0x0101: 'RSASSA-PSS-SHA256', 0x0102: 'RSASSA-PSS-SHA512',
              0x0103: 'RSA-PKCS1-SHA256', 0x0104: 'RSA-PKCS1-SHA512',
              0x0201: 'ECDSA-SHA256', 0x0202: 'ECDSA-SHA512', 0x0301: 'DSA-SHA256'}
_SIG_DIGEST = {0x0101: 1, 0x0103: 1, 0x0201: 1, 0x0301: 1,
               0x0102: 2, 0x0104: 2, 0x0202: 2}
_DIGEST_FN = {1: hashlib.sha256, 2: hashlib.sha512}
_SIG_V2_ID = 0x7109871A
_SIG_V3_ID = 0xF05368C0
_SIG_V31_ID = 0x1B93AD61
_STRIPPING_PROTECTION_ATTR_ID = 0xBEEFF00D

def _lp(buf, off):
    ln = struct.unpack_from('<I', buf, off)[0]
    if ln > len(buf) - off - 4:
        raise PullError('verify', 'malformed length-prefixed value in signature block')
    return buf[off + 4:off + 4 + ln], off + 4 + ln

def _id_value_seq(buf):
    """AOSP parseIdValues: concatenated records, each lp(u32 id + lp value)."""
    items, off = [], 0
    while off < len(buf):
        rec, off = _lp(buf, off)
        if len(rec) < 4:
            raise PullError('verify', 'malformed record in signature block')
        algo = struct.unpack_from('<I', rec, 0)[0]
        val, voff = _lp(rec, 4)
        if voff != len(rec):
            raise PullError('verify', 'malformed record in signature block')
        items.append((algo, val))
    return items

def _cert_seq(buf):
    """AOSP: concatenated lp(DER cert)."""
    certs, off = [], 0
    while off < len(buf):
        c, off = _lp(buf, off)
        certs.append(c)
    if not certs:
        raise PullError('verify', 'signature block has no certificates')
    return certs

def _find_eocd(data):
    """AOSP ZipUtils: a candidate EOCD is valid only if its comment length makes
    the record end EXACTLY at end of file - anything appended after the record
    (or a corrupted comment length) means no EOCD at all."""
    pos = max(0, len(data) - (22 + 65535))
    while True:
        i = data.find(b'PK\x05\x06', pos)
        if i < 0 or i + 22 > len(data):
            raise PullError('verify', 'no ZIP end-of-central-directory record ending at EOF - '
                            'not a zip, or bytes were appended after it')
        clen = struct.unpack_from('<H', data, i + 20)[0]
        if i + 22 + clen == len(data):
            return i
        pos = i + 1

def _sig_block(data):
    """-> (pairs dict, block_start, eocd_off, cd_off); raises if no signing block."""
    eocd_off = _find_eocd(data)
    cd_off = struct.unpack_from('<I', data, eocd_off + 16)[0]
    if data[cd_off - 16:cd_off] != b'APK Sig Block 42':
        raise PullError('verify', 'no APK Signing Block - not v2/v3 signed; v1-only files are rejected')
    size2 = struct.unpack_from('<Q', data, cd_off - 24)[0]
    block_start = cd_off - size2 - 8
    if block_start < 0 or struct.unpack_from('<Q', data, block_start)[0] != size2:
        raise PullError('verify', 'corrupt APK Signing Block')
    pairs, off, end = {}, block_start + 8, cd_off - 24
    while off < end:
        ln = struct.unpack_from('<Q', data, off)[0]
        pid = struct.unpack_from('<I', data, off + 8)[0]
        pairs[pid] = data[off + 12:off + 8 + ln]
        off += 8 + ln
    return pairs, block_start, eocd_off, cd_off

def _content_digest(data, block_start, eocd_off, cd_off, hashfn):
    """Digest over the three zip sections; the EOCD section is the FULL record
    (including any zip comment) with the central-directory offset patched to
    point at the signing block, exactly as apksig digests it."""
    eocd = bytearray(data[eocd_off:])
    eocd[16:20] = struct.pack('<I', block_start)
    ranges = [(0, block_start), (cd_off, eocd_off)]
    chunks = []
    for a, b in ranges:
        j = a
        while j < b:
            piece = data[j:min(j + 1048576, b)]
            h = hashfn()
            h.update(b'\xa5' + struct.pack('<I', len(piece)) + piece)
            chunks.append(h.digest())
            j += 1048576
    for j in range(0, len(eocd), 1048576):
        piece = bytes(eocd[j:j + 1048576])
        h = hashfn()
        h.update(b'\xa5' + struct.pack('<I', len(piece)) + piece)
        chunks.append(h.digest())
    h = hashfn()
    h.update(b'\x5a' + struct.pack('<I', len(chunks)) + b''.join(chunks))
    return h.digest()

def _verify_one_sig(algo, public_key, sig, signed_data):
    if algo in (0x0101, 0x0102):
        h = hashes.SHA256() if algo == 0x0101 else hashes.SHA512()
        public_key.verify(sig, signed_data,
                          padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
    elif algo in (0x0103, 0x0104):
        h = hashes.SHA256() if algo == 0x0103 else hashes.SHA512()
        public_key.verify(sig, signed_data, padding.PKCS1v15(), h)
    elif algo in (0x0201, 0x0202):
        h = hashes.SHA256() if algo == 0x0201 else hashes.SHA512()
        public_key.verify(sig, signed_data, ec.ECDSA(h))
    elif algo == 0x0301:
        public_key.verify(sig, signed_data, hashes.SHA256())
    else:
        raise InvalidSignature('unsupported algo 0x%04x' % algo)

def _parse_signer_v2(s):
    sd, o = _lp(s, 0)
    sigs, o = _lp(s, o)
    pk, o = _lp(s, o)
    dig, o2 = _lp(sd, 0)
    certs_b, o2 = _lp(sd, o2)
    attrs_b, o2 = _lp(sd, o2)
    return sd, sigs, pk, dig, certs_b, attrs_b, None, None

def _parse_signer_v3(s):
    sd, o = _lp(s, 0)
    sdk_min = struct.unpack_from('<I', s, o)[0]
    sdk_max = struct.unpack_from('<I', s, o + 4)[0]
    o += 8
    sigs, o = _lp(s, o)
    pk, o = _lp(s, o)
    dig, o2 = _lp(sd, 0)
    certs_b, o2 = _lp(sd, o2)
    sd_min = struct.unpack_from('<I', sd, o2)[0]
    sd_max = struct.unpack_from('<I', sd, o2 + 4)[0]
    o2 += 8
    attrs_b, o2 = _lp(sd, o2)
    # AOSP V3_SIG_*_SDK_VERSION_MISMATCH_BETWEEN_SIGNER_AND_SIGNED_DATA_RECORD
    if sdk_min != sd_min or sdk_max != sd_max:
        raise PullError('verify', 'v3 SDK range in signer (%s-%s) disagrees with signed data '
                        '(%s-%s)' % (sdk_min, sdk_max, sd_min, sd_max))
    if sdk_min > sdk_max:
        raise PullError('verify', 'v3 SDK range invalid (min %s > max %s)' % (sdk_min, sdk_max))
    return sd, sigs, pk, dig, certs_b, attrs_b, sdk_min, sdk_max

def _verify_scheme(data, block, ver, block_start, eocd_off, cd_off):
    # signers: lp(sequence) then lp(signer) per signer (AOSP parseSigners)
    seq, consumed = _lp(block, 0)
    if consumed != len(block):
        raise PullError('verify', 'malformed signers sequence in signature block')
    signers, off = [], 0
    while off < len(seq):
        st, off = _lp(seq, off)
        signers.append(st)
    if not signers:
        raise PullError('verify', 'signature block has no signers')
    parse = _parse_signer_v2 if ver == 2 else _parse_signer_v3
    first_fp, first_subj = None, None
    referenced_schemes = set()
    for s in signers:
        sd, sigs, pk, dig, certs_b, attrs_b, sdk_min, sdk_max = parse(s)
        signatures = _id_value_seq(sigs)
        digests = _id_value_seq(dig)
        if not signatures:
            raise PullError('verify', 'no signatures in signer record')
        # AOSP: the ordered algorithm lists of the signatures and digests
        # records must agree exactly.
        if [a for a, _ in signatures] != [a for a, _ in digests]:
            raise PullError('verify', 'signature algorithm IDs do not match between '
                            'signatures and digests records')
        certs = _cert_seq(certs_b)
        try:
            cert = _x509.load_der_x509_certificate(certs[0])
        except ValueError:
            raise PullError('verify', 'malformed signing certificate')
        pubkey = cert.public_key()
        if pubkey.public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo) != pk:
            raise PullError('verify', 'public key mismatch between certificate and signatures record')
        # verify signatures; unknown algorithms are skipped with a warning (AOSP
        # behavior), at least one supported signature must verify.
        verified_algos = []
        for algo, sig in signatures:
            if algo not in _SIG_ALGOS:
                print('verify warning: unknown signature algorithm 0x%04x - skipped' % algo)
                continue
            try:
                _verify_one_sig(algo, pubkey, sig, sd)
                verified_algos.append(algo)
            except InvalidSignature:
                raise PullError('verify', 'v%d signature (algo 0x%04x) DID NOT VERIFY' % (ver, algo))
        if not verified_algos:
            raise PullError('verify', 'no supported v%d signatures' % ver)
        # content digest must match for every verified signature's algorithm
        for algo in verified_algos:
            stored = dict(digests)[algo]
            computed = _content_digest(data, block_start, eocd_off, cd_off,
                                       _DIGEST_FN[_SIG_DIGEST[algo]])
            if computed != stored:
                raise PullError('verify', 'CONTENT DIGEST MISMATCH - file was modified after signing')
        # stripping-protection attribute: ids of newer schemes this file claims
        # to also be signed with (AOSP: referenced scheme must be present)
        aoff = 0
        while aoff < len(attrs_b):
            attr, aoff = _lp(attrs_b, aoff)
            if len(attr) >= 4 and struct.unpack_from('<I', attr, 0)[0] == _STRIPPING_PROTECTION_ATTR_ID:
                if len(attr) >= 8:
                    referenced_schemes.add(struct.unpack_from('<I', attr, 4)[0])
        fp = hashlib.sha256(certs[0]).hexdigest().upper()
        if first_fp is None:
            first_fp = fp
            first_subj = cert.subject.rfc4514_string()
        elif fp != first_fp:
            raise PullError('verify', 'multiple signers with different certificates')
    return first_fp, first_subj, referenced_schemes

def apk_verify_signature(path):
    """Cryptographically verify the APK's signature and content digest, mirroring
    apksig. Prefers v3 over v2 when both exist (AOSP order). Returns
    (signer cert sha256 hex, subject). Raises PullError on any failure."""
    data = open(path, 'rb').read()
    pairs, block_start, eocd_off, cd_off = _sig_block(data)
    def _check_refs(refs, ver):
        missing = {i for i in refs if i in (_SIG_V2_ID, _SIG_V3_ID, _SIG_V31_ID)} - set(pairs)
        if missing:
            raise PullError('verify', 'v%d block claims the file is also signed with scheme(s) %s '
                            'but those blocks are missing - the file was tampered with'
                            % (ver, ['0x%08x' % i for i in sorted(missing)]))
    if _SIG_V3_ID in pairs:
        fp, subj, refs = _verify_scheme(data, pairs[_SIG_V3_ID], 3, block_start, eocd_off, cd_off)
        _check_refs(refs, 3)
        return fp, subj
    if _SIG_V2_ID in pairs:
        fp, subj, refs = _verify_scheme(data, pairs[_SIG_V2_ID], 2, block_start, eocd_off, cd_off)
        _check_refs(refs, 2)
        return fp, subj
    if _SIG_V31_ID in pairs:
        raise PullError('verify', 'only a v3.1 (key rotation) signature is present - '
                        'lineage verification is not implemented; refusing the file')
    raise PullError('verify', 'APK has no v2/v3 signature')

def apk_manifest(apk_path):
    from androguard.core.apk import APK
    return APK(apk_path)

def verify(cfg, pkg, want, pin_arg, outdir, vc, files):
    # 1. cryptographic signature verification on EVERY split
    signers, subjects = {}, {}
    for name in files:
        fp, subj = apk_verify_signature(os.path.join(outdir, name))
        signers[name] = fp
        subjects[name] = subj
        print('verify signature OK (%s)' % name)
    if len(set(signers.values())) != 1:
        raise PullError('verify', 'splits signed by DIFFERENT certificates %s - do NOT use these files'
                        % {k: v[:12] for k, v in signers.items()})
    sha256 = signers.get('base.apk') or list(signers.values())[0]
    subj = subjects.get('base.apk') or list(subjects.values())[0]
    # 2. package + version checks on the base APK
    a = apk_manifest(os.path.join(outdir, 'base.apk'))
    if a.get_package() != pkg:
        raise PullError('verify', 'package mismatch: got %s, wanted %s - do NOT use these files'
                        % (a.get_package(), pkg))
    print('verify package  OK (%s)' % pkg)
    actual_vc = int(a.get_androidversion_code())
    if actual_vc != int(vc):
        raise PullError('verify', 'versionCode mismatch: APK has %s, Play served %s - '
                        'do NOT use these files' % (actual_vc, vc))
    print('verify version  OK (%s, vc %s)' % (a.get_androidversion_name(), actual_vc))
    if want and not a.get_androidversion_name().startswith(want):
        raise PullError('verify', 'version mismatch: got %s, wanted prefix %s'
                        % (a.get_androidversion_name(), want))
    # 3. signer trust
    print('signer sha256   %s' % sha256)
    print('signer subject  %s' % subj)
    pin = (pin_arg or (cfg.get('pins') or {}).get(pkg) or '').upper()
    if pin:
        if sha256 != pin:
            raise PullError('verify', 'SIGNER MISMATCH: got %s, pinned %s - do NOT use these files'
                            % (sha256[:16] + '...', pin[:16] + '...'))
        if pin_arg:
            cfg.setdefault('pins', {})[pkg] = pin
            save_config(cfg)
        print('verify signer   OK (matches pinned certificate - authenticated)')
    else:
        print('verify signer   UNVERIFIED (TOFU) - signature is valid but the signer is not pinned:')
        print('                authenticity NOT established until you confirm this certificate')
        print('                out-of-band, then pin it:')
        print('                python3 pull.py pull %s %s --pin-sha256 %s' % (pkg, want or '', sha256))

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
        get_details(api, 'com.google.android.calculator')
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
            refresh_checkin(cfg)   # raises on failure; no false "refreshed"
            print('checkin refreshed')
        else:
            print(USAGE)
    except PullError as e:
        die(e)
