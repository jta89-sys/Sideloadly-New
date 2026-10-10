import datetime as dt
import hashlib
import http.client
import json
from pathlib import Path
import plistlib
import ssl
import struct
import tempfile
import threading
import unittest
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from core import inspect_ipa, read_profile, validate_identity
from server import Inbox, LocalServer, make_tls


def fixture_ipa(path, extras=None, encrypted=False):
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1 if encrypted else 0,
                         24 if encrypted else 0, 0, 0)
    if encrypted:
        header += struct.pack("<IIIIII", 0x2C, 24, 0, 0, 1, 0)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Test.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.example.test",
                          "CFBundleExecutable": "Test", "CFBundleName": "Test"}))
        archive.writestr("Payload/Test.app/Test", header)
        for name, content in (extras or {}).items():
            archive.writestr(name, content)


def identity(directory, bundle="com.example.*"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SideBridge TEST ROOT — NOT APPLE")])
    root_cert = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name).public_key(root_key.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
                 .not_valid_after(now + dt.timedelta(days=3))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                 .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                              data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                              crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
                 .sign(root_key, hashes.SHA256()))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SideBridge TEST ONLY")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(root_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=2))
            # macOS code-signing policy rejects leaf certs lacking these (Invalid Key Usage for policy).
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
            .sign(root_key, hashes.SHA256()))
    profile = {"Name": "SideBridge TEST ONLY — cannot install on a real iPad", "UUID": "11111111-2222-3333-4444-555555555555",
               "TeamIdentifier": ["TESTTEAM01"], "ApplicationIdentifierPrefix": ["TESTTEAM01"],
               "CreationDate": now.replace(tzinfo=None), "ExpirationDate": (now + dt.timedelta(days=1)).replace(tzinfo=None),
               "DeveloperCertificates": [cert.public_bytes(serialization.Encoding.DER)],
               "ProvisionedDevices": ["test-device"], "Platform": ["iOS"], "Version": 1,
               "Entitlements": {"application-identifier": "TESTTEAM01." + bundle,
                                "com.apple.developer.team-identifier": "TESTTEAM01", "get-task-allow": True,
                                "keychain-access-groups": ["TESTTEAM01.*"]}}
    p12 = directory / "test.p12"
    p12.write_bytes(pkcs12.serialize_key_and_certificates(b"test", key, cert, [root_cert],
                    serialization.BestAvailableEncryption(b"test-password")))
    provision = directory / "test.mobileprovision"
    provision.write_bytes(pkcs7.PKCS7SignatureBuilder().set_data(plistlib.dumps(profile))
                          .add_signer(cert, key, hashes.SHA256()).sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
    return p12, provision, profile


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.ipa = self.folder / "app.ipa"
        fixture_ipa(self.ipa)

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_ipa(self):
        self.assertEqual(inspect_ipa(self.ipa)["bundle"], "com.example.test")

    def test_signing_identity_certificate_usage(self):
        p12, _, _ = identity(self.folder)
        _, leaf, chain = pkcs12.load_key_and_certificates(p12.read_bytes(), b"test-password")
        self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.digital_signature)
        self.assertFalse(usage.key_cert_sign)
        self.assertIn(ExtendedKeyUsageOID.CODE_SIGNING,
                      leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
        self.assertEqual(len(chain), 1)
        self.assertTrue(chain[0].extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertTrue(chain[0].extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)

    def test_path_traversal(self):
        fixture_ipa(self.ipa, {"../../outside.txt": "bad"})
        with self.assertRaises(ValueError): inspect_ipa(self.ipa)

    def test_windows_path_aliases(self):
        for name in ("Payload/Test.app/.. /outside", "Payload/Test.app/CON.txt", "Payload/Test.app/./file"):
            fixture_ipa(self.ipa, {name: "bad"})
            with self.assertRaises(ValueError): inspect_ipa(self.ipa)

    def test_extensions_rejected_without_modifying_source(self):
        fixture_ipa(self.ipa, {"Payload/Test.app/PlugIns/Widget.appex/Info.plist": b"test"})
        before = self.ipa.read_bytes()
        with self.assertRaises(ValueError): inspect_ipa(self.ipa)
        self.assertEqual(before, self.ipa.read_bytes())

    def test_encrypted_app(self):
        fixture_ipa(self.ipa, encrypted=True)
        with self.assertRaisesRegex(ValueError, "Encrypted"): inspect_ipa(self.ipa)

    def test_identity_and_profile(self):
        p12, profile_file, profile = identity(self.folder)
        loaded = read_profile(profile_file)
        self.assertEqual(loaded["UUID"], profile["UUID"])
        validate_identity(p12, "test-password", loaded, "com.example.test", "test-device")
        with self.assertRaisesRegex(ValueError, "not registered"):
            validate_identity(p12, "test-password", loaded, "com.example.test", "other-device")
        with self.assertRaisesRegex(ValueError, "does not cover"):
            validate_identity(p12, "test-password", loaded, "org.other.test", "test-device")
        with self.assertRaises(ValueError):
            validate_identity(p12, "wrong-password", loaded, "com.example.test", "test-device")
        loaded["ExpirationDate"] = dt.datetime(2000, 1, 1)
        with self.assertRaisesRegex(ValueError, "expired"):
            validate_identity(p12, "test-password", loaded, "com.example.test", "test-device")

    def test_mismatched_cert_and_store_profile(self):
        p12, _, profile = identity(self.folder)
        profile["DeveloperCertificates"] = []
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_identity(p12, "test-password", profile, "com.example.test", None)
        p12, _, profile = identity(self.folder)
        profile.pop("ProvisionedDevices")
        with self.assertRaisesRegex(ValueError, "App Store"):
            validate_identity(p12, "test-password", profile, "com.example.test", None)


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.inbox = Inbox(self.folder / "inbox")
        tls, self.fingerprint = make_tls(self.folder)
        self.server = LocalServer(("127.0.0.1", 0), self.inbox, tls)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path, method="GET", body=None, token=True):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Test client verifies the exact certificate fingerprint below.
        connection = http.client.HTTPSConnection("127.0.0.1", self.server.server_port, context=context, timeout=5)
        connection.connect()
        self.assertEqual(hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest(), self.fingerprint)
        headers = {"Authorization": "Bearer " + self.server.token} if token else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        status, data = response.status, json.loads(response.read())
        connection.close()
        return status, data

    def test_auth_and_status(self):
        self.assertEqual(self.request("/v1/status", token=False)[0], 401)
        status, data = self.request("/v1/status")
        self.assertEqual(status, 200)
        self.assertEqual(data["jobs"], [])
        self.assertEqual(self.request("/wrong")[0], 404)

    def test_upload_and_integrity(self):
        file = self.folder / "source.ipa"
        fixture_ipa(file)
        data = file.read_bytes()
        status, result = self.request("/v1/upload", "POST", data)
        self.assertEqual(status, 201)
        self.assertEqual((self.inbox.directory / (result["id"] + ".ipa")).read_bytes(), data)
        self.assertEqual(self.request("/v1/status")[1]["jobs"][0]["status"], "Waiting for Windows")
        self.assertFalse(list(self.inbox.directory.glob("*.upload")))

    def test_reject_bad_upload_and_cleanup(self):
        self.assertEqual(self.request("/v1/upload", "POST", b"not an ipa")[0], 400)
        self.assertFalse(list(self.inbox.directory.iterdir()))
        self.assertEqual(self.request("/v1/upload", "POST", b"")[0], 413)


if __name__ == "__main__":
    unittest.main()

