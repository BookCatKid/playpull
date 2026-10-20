"""Fixture matrix test for pull.py's signature verifier.

Builds 11 known-good/known-bad APKs with sigfix.FixtureSigner and checks that
pull.apk_verify_signature accepts/rejects each exactly as Android's reference
apksigner does. Self-contained and offline: python3 tests/run_fixtures.py

Optional cross-check against the real apksigner jar (needs Java):
  python3 tests/run_fixtures.py --apksigner-jar /path/to/apksigner.jar --manifest-apk any-real.apk
(apksigner refuses APKs without a binary AndroidManifest.xml, so the fixtures
borrow one from any real APK for that mode.)
"""
import os, sys, tempfile, subprocess, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sigfix
import pull

def build_fixtures(s, manifest=None):
    z = s.build_zip(manifest=manifest)
    zc = s.build_zip(comment=b'hello', manifest=manifest)
    f = {}
    f['f1_v2_single'] = s.assemble(z, [s.v2(z)])
    f['f2_v2_multialgo'] = s.assemble(z, [s.v2(z, algos=(0x0103, 0x0101))])
    f['f3_v2_comment'] = s.assemble(zc, [s.v2(zc)])
    f['f4_trailing_garbage'] = f['f1_v2_single'] + b'GARBAGE!!'
    b = bytearray(f['f3_v2_comment'])
    i = bytes(b).rfind(b'hello')
    b[i:i + 5] = b'jello'
    f['f5_comment_modified'] = bytes(b)
    b = bytearray(f['f1_v2_single'])
    b[100] ^= 0xFF
    f['f6_content_flip'] = bytes(b)
    f['f7_v3_only'] = s.assemble(z, [s.v3(z)])
    f['f8_v3_sdk_mismatch'] = s.assemble(z, [s.v3(z, sdk=(28, 100, 28, 99))])
    f['f9_v2v3_dual'] = s.assemble(z, [s.v3(z), s.v2(z)])
    f['f10_v2_algo_list_mismatch'] = s.assemble(z, [s.v2(z, extra_digest_algos=(0x0104,))])
    f['f11_v31_only_no_lineage'] = s.assemble(z, [s.v31(z)])
    return f

EXPECTED = {'f1_v2_single': True, 'f2_v2_multialgo': True, 'f3_v2_comment': True,
            'f4_trailing_garbage': False, 'f5_comment_modified': False,
            'f6_content_flip': False, 'f7_v3_only': True, 'f8_v3_sdk_mismatch': False,
            'f9_v2v3_dual': True, 'f10_v2_algo_list_mismatch': False,
            'f11_v31_only_no_lineage': False}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apksigner-jar')
    ap.add_argument('--manifest-apk')
    args = ap.parse_args()
    if args.apksigner_jar and not args.manifest_apk:
        ap.error('--apksigner-jar needs --manifest-apk (any real APK, for its AndroidManifest.xml)')
    manifest = None
    if args.manifest_apk:
        import zipfile
        manifest = zipfile.ZipFile(args.manifest_apk).read('AndroidManifest.xml')
    s = sigfix.FixtureSigner()
    fixtures = build_fixtures(s, manifest)
    failures = 0
    with tempfile.TemporaryDirectory() as td:
        for name, data in sorted(fixtures.items()):
            path = os.path.join(td, name + '.apk')
            open(path, 'wb').write(data)
            try:
                pull.apk_verify_signature(path)
                mine = True
            except pull.PullError:
                mine = False
            want = EXPECTED[name]
            line = '%-30s playpull=%-6s expected=%-6s' % (name, 'ACCEPT' if mine else 'REJECT',
                                                          'ACCEPT' if want else 'REJECT')
            if args.apksigner_jar:
                r = subprocess.run(['java', '-jar', args.apksigner_jar, 'verify',
                                    '--min-sdk-version', '28', '--max-sdk-version', '34', path],
                                   capture_output=True)
                ref = r.returncode == 0
                line += ' apksigner=%-6s' % ('ACCEPT' if ref else 'REJECT')
                if ref != want:
                    line += ' *** APKSIGNER DISAGREES WITH MATRIX ***'
                    failures += 1
            if mine != want:
                line += ' *** FAIL ***'
                failures += 1
            else:
                line += ' ok'
            print(line)
    print('PASS' if not failures else 'FAILURES: %d' % failures)
    sys.exit(0 if not failures else 1)

if __name__ == '__main__':
    main()
