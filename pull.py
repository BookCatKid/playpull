#!/usr/bin/env python3
"""Pure-python Google Play puller. No emulator needed once an AAS token exists.

Usage:
    pull.py check           -> print the version Play would serve this account/device
    pull.py pull [prefix]   -> purchase + download + verify all splits for the package

Files in this directory:
    config.json   - email, gsf_id, package, expected signer sha256 (see config.example.json)
    aas_token     - AAS master token (mint with mint_aas.py; lives for weeks-months)

Flow (reproduced from a real Android 13 emulator + GMS):
    AAS token -> oauth2:<googleplay-scope> token -> FDFE uploadDeviceConfig
              -> details -> purchase (free acquire) -> delivery -> signed download URLs
"""
import sys, os, json, requests
import gpsoauth
from gpapi.googleplay import GooglePlayAPI
from gpapi.config import DeviceBuilder
from gpapi import googleplay_pb2

DIR = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(DIR, 'config.json')))
PKG = CFG.get('package', 'com.sonos.acr2')

# Device profile copied from the real device this gsf_id belongs to (Android 13 arm64).
# FDFE rejects stale/ inconsistent client fingerprints with DF-DFERH-01: the Finsky
# version in the User-Agent must be current, and the profile must be self-consistent.
DEVICE_PROFILE = {
 'build.hardware': 'redroid', 'build.brand': 'redroid', 'build.device': 'redroid13_arm64_only',
 'build.version.sdk_int': '33', 'build.model': 'redroid13_arm64_only', 'build.manufacturer': 'redroid',
 'build.product': 'redroid_arm64_only', 'build.id': 'TQ3A.230805.001.S1', 'build.version.release': '13',
 'build.fingerprint': 'redroid/redroid_arm64_only/redroid_arm64_only:13/TQ3A.230805.001.S1/eng.frank.20240527.134411:userdebug/test-keys',
 'platforms': 'arm64-v8a', 'screen.density': '320', 'screen.width': '720', 'screen.height': '1280',
 'gl.version': '196610', 'gsf.version': '264032029',
 'vending.version': '85361530', 'vending.versionstring': '53.6.15-31 [0] [PR] 996698724',
 'celloperator': '', 'simoperator': '', 'timezone': 'America/Los_Angeles',
}
GMS_CLIENT_SIG = '38918a453d07199354f8b19af05ec6562ced5788'  # GMS package signature hash (public)

def build_api():
    aas = open(os.path.join(DIR, 'aas_token')).read().strip()
    r = gpsoauth.perform_oauth(CFG['email'], aas, CFG['gsf_id'],
        service='oauth2:https://www.googleapis.com/auth/googleplay',
        app='com.android.vending', client_sig=GMS_CLIENT_SIG,
        device_country='us', operator_country='us', lang='en', sdk_version=29)
    if 'Error' in r:
        raise SystemExit('AAS expired or rejected: %s - re-mint with mint_aas.py' % r)
    b = DeviceBuilder('bacon')  # any base section; we override every field that matters
    b.locale = 'en_US'; b.timezone = 'PST8PDT'
    b.device.update(DEVICE_PROFILE)
    api = GooglePlayAPI('en_US', 'PST8PDT')
    api.deviceBuilder = b
    api.gsfId = int(CFG['gsf_id'])
    api.setAuthSubToken(r['Auth'])
    api.uploadDeviceConfig()
    return api, api.getHeaders()

def served_version(api):
    d = api.details(PKG)
    doc = d.get('docV2', d) if isinstance(d, dict) else d.docV2
    det = doc['details']['appDetails'] if isinstance(doc, dict) else doc.details.appDetails
    return (det.get('versionString') if isinstance(det, dict) else det.versionString,
            det.get('versionCode') if isinstance(det, dict) else det.versionCode)

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'check'
    api, headers = build_api()
    vs, vc = served_version(api)
    print('served: %s (vc %s)' % (vs, vc))
    if mode == 'check':
        sys.exit(0)
    want = sys.argv[2] if len(sys.argv) > 2 else ''
    if want and want not in vs:
        print('prefix %r not in served version - not pulling' % want)
        sys.exit(2)
    headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
    pr = requests.post('https://android.clients.google.com/fdfe/purchase', headers=headers,
                       data={'ot': '1', 'doc': PKG, 'vc': str(vc)}, timeout=30)
    br = googleplay_pb2.ResponseWrapper.FromString(pr.content).payload.buyResponse
    # server-side record of the app's signing cert (sha1) - second verification vector
    try:
        ch = br.purchaseStatusResponse.libraryUpdate.mutation[0].appDetails.certificateHash
        print('server cert sha1:', __import__('base64').b64decode(ch + '==').hex())
    except Exception:
        pass
    dl = requests.get('https://android.clients.google.com/fdfe/delivery', headers=headers,
                      params={'doc': PKG, 'vc': str(vc), 'ot': '1', 'dtok': br.downloadToken}, timeout=30)
    dd = googleplay_pb2.ResponseWrapper.FromString(dl.content).payload.deliveryResponse.appDeliveryData
    cookie = '; '.join('%s=%s' % (c.name, c.value) for c in dd.downloadAuthCookie)
    targets = [('base.apk', dd.downloadUrl)] + [('split_%s.apk' % s.name, s.downloadUrl) for s in dd.split]
    for name, url in targets:
        r = requests.get(url, headers={'Cookie': cookie}, timeout=300)
        r.raise_for_status()
        open(os.path.join(DIR, name), 'wb').write(r.content)
        print('downloaded', name, len(r.content))
    from androguard.core.apk import APK
    a = APK(os.path.join(DIR, 'base.apk'))
    certs = list(a.get_certificates())
    sha256 = certs[0].sha256_fingerprint.replace(' ', '').upper() if certs else ''
    ok = (a.get_package() == PKG and (not want or want in a.get_androidversion_name())
          and sha256 == CFG['expected_signer_sha256'].upper())
    print('VERIFY pkg=%s vn=%s signer=%s... -> %s'
          % (a.get_package(), a.get_androidversion_name(), sha256[:16], 'GENUINE' if ok else 'MISMATCH'))
    sys.exit(0 if ok else 3)
