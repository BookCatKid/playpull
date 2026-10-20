"""Test fixture builder: a minimal pure-python APK Signature Scheme v2/v3 SIGNER.

Exists only to produce known-good and known-bad APKs for run_fixtures.py.
Generates a fresh throwaway RSA key + self-signed cert on every run - no key
material is stored. The block layout mirrors AOSP ApkSigningBlockUtils /
V2/V3SchemeVerifier (the same sources pull.py's verifier mirrors).
"""
import io, struct, hashlib, zipfile, os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime

def _lp(b):
    return struct.pack('<I', len(b)) + b

def _u32(n):
    return struct.pack('<I', n)

class FixtureSigner:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Fixture Test')])
        self.cert = (x509.CertificateBuilder()
                     .subject_name(name).issuer_name(name)
                     .public_key(self.key.public_key())
                     .serial_number(1)
                     .not_valid_before(datetime.datetime(2020, 1, 1))
                     .not_valid_after(datetime.datetime(2050, 1, 1))
                     .sign(self.key, hashes.SHA256()))
        self.cert_der = self.cert.public_bytes(serialization.Encoding.DER)
        self.pk_der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def _sign(self, algo, data):
        if algo == 0x0101:  # RSASSA-PSS-SHA256
            return self.key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                   salt_length=32), hashes.SHA256())
        if algo == 0x0103:  # RSASSA-PKCS1-SHA256
            return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        raise ValueError(algo)

    @staticmethod
    def _content_digest(sections):
        chunks = []
        for sec in sections:
            for j in range(0, len(sec), 1048576):
                piece = sec[j:j + 1048576]
                h = hashlib.sha256()
                h.update(b'\xa5' + _u32(len(piece)) + piece)
                chunks.append(h.digest())
        h = hashlib.sha256()
        h.update(b'\x5a' + _u32(len(chunks)) + b''.join(chunks))
        return h.digest()

    @staticmethod
    def build_zip(comment=b'', manifest=None):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            if manifest:
                z.writestr('AndroidManifest.xml', manifest)
            z.writestr('classes.dex', b'dex\n035\x00' + os.urandom(64))
            z.writestr('res/data.bin', os.urandom(2048))
            z.comment = comment
        return buf.getvalue()

    @staticmethod
    def _split_zip(zip_bytes):
        eocd_off = zip_bytes.rfind(b'PK\x05\x06')
        cd_off = struct.unpack_from('<I', zip_bytes, eocd_off + 16)[0]
        return zip_bytes[:cd_off], zip_bytes[cd_off:eocd_off], zip_bytes[eocd_off:], cd_off

    def _pair(self, zip_bytes, scheme, algos=(0x0103,), sdk=None, extra_digest_algos=None):
        entries, cd, eocd, _ = self._split_zip(zip_bytes)
        eocd_patched = bytearray(eocd)
        eocd_patched[16:20] = _u32(len(entries))  # CD offset -> signing block start
        sections = [entries, cd, bytes(eocd_patched)]
        digest_algos = list(algos) + list(extra_digest_algos or ())
        digests = b''
        for a in digest_algos:
            digests += _lp(_u32(a) + _lp(self._content_digest(sections)))
        certs = _lp(self.cert_der)
        attrs = b''
        if scheme == 2:
            sd = _lp(digests) + _lp(certs) + _lp(attrs)
            sigs = b''.join(_lp(_u32(a) + _lp(self._sign(a, sd))) for a in algos)
            signer = _lp(sd) + _lp(sigs) + _lp(self.pk_der)
            pid = 0x7109871A
        else:
            sd_min, sd_max, sg_min, sg_max = sdk
            sd = _lp(digests) + _lp(certs) + _u32(sd_min) + _u32(sd_max) + _lp(attrs)
            sigs = b''.join(_lp(_u32(a) + _lp(self._sign(a, sd))) for a in algos)
            signer = _lp(sd) + _u32(sg_min) + _u32(sg_max) + _lp(sigs) + _lp(self.pk_der)
            pid = 0xF05368C0
        value = _lp(_lp(signer))
        return struct.pack('<Q', 4 + len(value)) + struct.pack('<I', pid) + value

    @staticmethod
    def assemble(zip_bytes, pairs):
        entries, cd, eocd, cd_off = FixtureSigner._split_zip(zip_bytes)
        body = b''.join(pairs)
        size = len(body) + 24
        block = struct.pack('<Q', size) + body + struct.pack('<Q', size) + b'APK Sig Block 42'
        eocd2 = bytearray(eocd)
        eocd2[16:20] = _u32(cd_off + len(block))
        return entries + block + cd + bytes(eocd2)

    def v2(self, zip_bytes, algos=(0x0103,), extra_digest_algos=None):
        return self._pair(zip_bytes, 2, algos, extra_digest_algos=extra_digest_algos)

    def v3(self, zip_bytes, algos=(0x0103,), sdk=(28, 100, 28, 100)):
        return self._pair(zip_bytes, 3, algos, sdk=sdk)

    def v31(self, zip_bytes, algos=(0x0103,), sdk=(28, 100, 28, 100)):
        """v3.1 pair WITHOUT a lineage (invalid on its own - lineage is mandatory)."""
        p = self._pair(zip_bytes, 3, algos, sdk=sdk)
        return p[:8] + struct.pack('<I', 0x1B93AD61) + p[12:]
