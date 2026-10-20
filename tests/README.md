# tests

Offline fixture-matrix test for pull.py's APK signature verifier.

    python3 tests/run_fixtures.py

Builds 11 crafted APKs (valid v2/v3, multi-algorithm, zip comment, trailing
garbage, modified comment, flipped content byte, v3 SDK-range mismatch,
v2+v3 dual, signatures/digests algorithm-list mismatch, v3.1 without lineage)
and checks the verifier accepts/rejects each exactly as Android's reference
apksigner does. No network, no Java, no stored keys (a throwaway key is
generated per run).

To also run the reference apksigner jar over the same fixtures (needs Java and
any real APK to borrow a binary AndroidManifest.xml from):

    python3 tests/run_fixtures.py --apksigner-jar /path/to/apksigner.jar --manifest-apk real.apk
