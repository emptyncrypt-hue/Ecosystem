"""Synthetic fixtures verify rejection behavior; they are not hardware evidence."""
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SPEC = importlib.util.spec_from_file_location("yubikey_piv", Path(__file__).resolve().parents[1] / "scripts/yubikey_piv.py")
piv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(piv)


def certificate(subject, issuer, public_key, signing_key, ca=False, path_length=None, extensions=(), start=None, end=None):
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(start or now - timedelta(days=1)).not_valid_after(end or now + timedelta(days=365))
    builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), True)
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=not ca, data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), True)
    for extension in extensions:
        builder = builder.add_extension(extension, False)
    return builder.sign(signing_key, hashes.SHA256())


class ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.document_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.root = certificate("Synthetic OEM", "Synthetic OEM", cls.root_key.public_key(), cls.root_key, ca=True, path_length=1)
        # Factory f9 is a vendor attestation signer, not a normal intermediate CA.
        cls.device = certificate("Synthetic f9", "Synthetic OEM", cls.device_key.public_key(), cls.root_key)
        cls.leaf = cls.make_leaf()

    @classmethod
    def make_leaf(cls, *, firmware=b"\x05\x07\x04", policy=b"\x02\x02", public_key=None, signer=None):
        return certificate("YubiKey PIV Attestation 82", "Synthetic f9", public_key or cls.document_key.public_key(), signer or cls.device_key, extensions=[x509.UnrecognizedExtension(piv.FIRMWARE_OID, firmware), x509.UnrecognizedExtension(piv.POLICY_OID, policy)])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.trust = patch.object(piv, "load_trust_bundle", return_value=([self.root], []))
        self.trust.start()
        self.addCleanup(self.trust.stop)
        self.addCleanup(self.temporary.cleanup)
        self.enrollment = self.directory / "enrollment.json"
        self.record = {"version": 1, "provider": "yubikey-piv", "slot": "82", "keyId": piv._key_id(self.document_key.public_key()), "publicKeySpki": piv._b64(piv._spki(self.document_key.public_key())), "attestationCertificate": self.device.public_bytes(serialization.Encoding.PEM).decode(), "keyCertificate": self.leaf.public_bytes(serialization.Encoding.PEM).decode(), "firmware": [5, 7, 4], "pinPolicy": "ONCE", "touchPolicy": "ALWAYS"}
        piv._write_new(self.enrollment, self.record)

    def session(self, **changes):
        metadata = types.SimpleNamespace(key_type=7, pin_policy=2, touch_policy=2, generated=True, public_key=self.document_key.public_key())
        metadata.__dict__.update(changes)
        owner = self

        class Session:
            version = (5, 7, 4)
            pin_calls = 0
            decrypt_calls = 0

            def get_slot_metadata(self, slot):
                owner.assertEqual(slot, 0x82)
                return metadata

            def get_certificate(self, slot):
                owner.assertEqual(slot, 0xF9)
                return owner.device

            def attest_key(self, slot):
                owner.assertEqual(slot, 0x82)
                return owner.leaf

            def verify_pin(self, pin):
                self.pin_calls += 1
                if pin != "synthetic PIN":
                    raise RuntimeError("PIN and document must not be reflected")

            def decrypt(self, slot, ciphertext, padding):
                self.decrypt_calls += 1
                return owner.document_key.decrypt(ciphertext, padding)

        connection = types.SimpleNamespace(closed=False)
        connection.close = lambda: setattr(connection, "closed", True)
        return connection, Session()

    def provider(self, **changes):
        connection, session = self.session(**changes)
        with patch.object(piv, "_connect", return_value=(connection, session)):
            provider = piv.Provider(self.enrollment)
            provider.open("synthetic PIN")
        self.addCleanup(provider.close)
        return provider, connection, session

    def test_oem_endorsement_signature_and_exact_leaf_policies(self):
        self.assertEqual(piv.verify_attestation(self.leaf, self.device, self.document_key.public_key(), (5, 7, 4)), self.record["keyId"])
        for leaf, firmware in [
            (self.make_leaf(policy=b"\x02\x03"), (5, 7, 4)),
            (self.make_leaf(policy=b"\x01\x02"), (5, 7, 4)),
            (self.make_leaf(firmware=b"\x05\x02\x00"), (5, 2, 0)),
            (self.make_leaf(), (5, 7, 3)),
            (self.make_leaf(signer=self.root_key), (5, 7, 4)),
            (self.make_leaf(public_key=self.device_key.public_key()), (5, 7, 4)),
        ]:
            with self.assertRaises(Exception):
                piv.verify_attestation(leaf, self.device, self.document_key.public_key(), firmware)

    def test_untrusted_endorsements_expiry_and_path_constraints_fail(self):
        with patch.object(piv, "load_trust_bundle", return_value=([], [])):
            with self.assertRaises(piv.VerificationError):
                piv.verify_endorsement(self.device)
        expired = certificate("Synthetic f9", "Synthetic OEM", self.device_key.public_key(), self.root_key, start=datetime.now(timezone.utc) - timedelta(days=5), end=datetime.now(timezone.utc) - timedelta(days=1))
        with self.assertRaises(piv.VerificationError):
            piv.verify_endorsement(expired)
        intermediate = certificate("Intermediate", "Synthetic OEM", self.device_key.public_key(), self.root_key, ca=True, path_length=0)
        ca_device = certificate("Device CA", "Intermediate", self.document_key.public_key(), self.device_key, ca=True, path_length=0)
        with patch.object(piv, "load_trust_bundle", return_value=([self.root], [intermediate])):
            with self.assertRaises(piv.VerificationError):
                piv.verify_endorsement(ca_device)

    def test_hardware_unwrap_round_trip_pin_once_and_fresh_checks(self):
        envelope = piv.seal(self.enrollment, b"# Curated private context\n", "https://www.dunesub.de")
        provider, _, session = self.provider()
        self.assertEqual(provider.check(), self.record["keyId"])
        self.assertEqual(provider.decrypt(envelope), b"# Curated private context\n")
        self.assertEqual(provider.decrypt(envelope), b"# Curated private context\n")
        self.assertEqual(session.pin_calls, 1)
        self.assertEqual(session.decrypt_calls, 2)
        with self.assertRaises(piv.VerificationError):
            provider.open("synthetic PIN")
        self.assertEqual(session.pin_calls, 1)

    def test_software_origin_context_replay_ciphertext_tamper_and_wrong_token_fail(self):
        original = piv.seal(self.enrollment, b"private context", "https://www.dunesub.de")
        for field, value in [
            ("siteOrigin", "https://other.example"),
            ("path", "/llms.txt"),
            ("keyId", "sha256:" + "0" * 64),
            ("ciphertext", piv._b64(b"x" * 20)),
            ("wrappedKey", piv._b64(b"x" * 256)),
        ]:
            provider, connection, session = self.provider()
            with self.assertRaises(piv.VerificationError) as error:
                provider.decrypt({**original, field: value})
            self.assertTrue(connection.closed)
            self.assertNotIn("private context", str(error.exception))
            private_calls = session.decrypt_calls
            with self.assertRaises(piv.VerificationError):
                provider.decrypt(original)
            self.assertEqual(session.decrypt_calls, private_calls)

    def test_metadata_imported_keys_cached_touch_and_replaced_device_fail_before_pin(self):
        for changes in [{"generated": False}, {"touch_policy": 3}, {"pin_policy": 1}, {"key_type": 0x11}, {"public_key": self.device_key.public_key()}]:
            connection, session = self.session(**changes)
            with patch.object(piv, "_connect", return_value=(connection, session)):
                provider = piv.Provider(self.enrollment)
                with self.assertRaises(piv.VerificationError):
                    provider.open("synthetic PIN")
            self.assertEqual(session.pin_calls, 0)
            self.assertTrue(connection.closed)

    def test_wrong_pin_not_retried_or_retained(self):
        connection, session = self.session()
        with patch.object(piv, "_connect", return_value=(connection, session)):
            provider = piv.Provider(self.enrollment)
            with self.assertRaises(piv.VerificationError):
                provider.open("wrong PIN")
            with self.assertRaises(piv.VerificationError):
                provider.open("synthetic PIN")
        self.assertEqual(session.pin_calls, 1)
        self.assertTrue(connection.closed)
        self.assertNotIn("wrong PIN", repr(provider.__dict__))

    def test_noncanonical_envelope_oversize_binary_and_unsafe_origin_rejected(self):
        original = piv.seal(self.enrollment, b"valid", "https://www.dunesub.de")
        self.assertEqual(piv.validate_envelope(original, "https://www.dunesub.de/"), original)
        for envelope in [
            {**original, "version": True}, {**original, "version": 1},
            {**original, "extra": 1}, {**original, "nonce": original["nonce"] + "="},
            {**original, "nonce": "x" * 5000},
            {**original, "siteOrigin": "https://www.dunesub.de/"},
        ]:
            with self.assertRaises(piv.VerificationError):
                piv.validate_envelope(envelope)
        with self.assertRaises(piv.VerificationError):
            piv.validate_envelope(original, "https://different.example")
        for text in [b"", b"x" * 2049, b"\xff", b"contains\0NUL"]:
            with self.assertRaises(piv.VerificationError):
                piv.seal(self.enrollment, text, "https://www.dunesub.de")
        for origin in ["http://www.dunesub.de", "https://user@www.dunesub.de", "https://www.dunesub.de/private", "https://www.dunesub.de?x=1"]:
            with self.assertRaises(piv.VerificationError):
                piv.seal(self.enrollment, b"valid", origin)

    def test_seals_use_independent_keys_and_nonces_no_private_material_in_enrollment(self):
        first = piv.seal(self.enrollment, b"valid", "https://www.dunesub.de")
        second = piv.seal(self.enrollment, b"valid", "https://www.dunesub.de")
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["wrappedKey"], second["wrappedKey"])
        self.assertNotIn("PRIVATE KEY", json.dumps(self.record))
        self.assertEqual(os.stat(self.enrollment).st_mode & 0o777, 0o600)

    def test_protected_files_reject_world_readable_symlinks_and_overwrites(self):
        os.chmod(self.enrollment, 0o644)
        with self.assertRaises(piv.VerificationError):
            piv.load_enrollment(self.enrollment)
        os.chmod(self.enrollment, 0o600)
        link = self.directory / "link"
        link.symlink_to(self.enrollment)
        with self.assertRaises(piv.VerificationError):
            piv.load_enrollment(link)
        with self.assertRaises(FileExistsError):
            piv._write_new(self.enrollment, {})
        fifo = self.directory / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(piv.VerificationError):
            piv.load_enrollment(fifo)

    def test_output_symlink_parent_cannot_redirect_into_repository(self):
        directory_link = self.directory / "repository"
        directory_link.symlink_to(piv.ROOT, target_is_directory=True)
        with self.assertRaises(piv.VerificationError):
            piv._write_new(directory_link / "private-enrollment-do-not-create.json", {})

    def test_enrollment_schema_boolean_version_cannot_replace_integer(self):
        self.enrollment.write_text(json.dumps({**self.record, "version": True}))
        with self.assertRaises(piv.VerificationError):
            piv.load_enrollment(self.enrollment)

    def test_leaf_slot_subject_cannot_be_substituted(self):
        leaf = certificate("YubiKey PIV Attestation 9d", "Synthetic f9", self.document_key.public_key(), self.device_key, extensions=[x509.UnrecognizedExtension(piv.FIRMWARE_OID, b"\x05\x07\x04"), x509.UnrecognizedExtension(piv.POLICY_OID, b"\x02\x02")])
        with self.assertRaises(piv.VerificationError):
            piv.verify_attestation(leaf, self.device, self.document_key.public_key(), (5, 7, 4))

    def enrollment_session(self, *, occupied=False, wrong_missing_status=False, bad_challenge=False, wrong_pin=False, generation_response_error=False):
        from yubikit.core.smartcard import ApduError, SW
        owner = self
        metadata = types.SimpleNamespace(key_type=7, pin_policy=2, touch_policy=2, generated=True, public_key=self.document_key.public_key())

        class Session:
            version = (5, 7, 4)
            generated = False
            pin_calls = 0
            authentication_calls = 0
            generation_calls = 0

            def get_slot_metadata(self, slot):
                if occupied or self.generated:
                    return metadata
                raise ApduError(b"", SW.REFERENCE_DATA_NOT_FOUND)

            def get_certificate(self, slot):
                if slot == 0xF9:
                    return owner.device
                raise ApduError(b"", SW.REFERENCE_DATA_NOT_FOUND if wrong_missing_status else SW.FILE_NOT_FOUND)

            def authenticate(self, key):
                self.authentication_calls += 1
                owner.assertEqual(key, b"synthetic management key")

            def verify_pin(self, pin):
                self.pin_calls += 1
                if wrong_pin:
                    raise RuntimeError("wrong synthetic PIN")

            def generate_key(self, slot, key_type, pin_policy, touch_policy):
                self.generation_calls += 1
                self.generated = True
                owner.assertEqual((slot, int(key_type), int(pin_policy), int(touch_policy)), (0x82, 7, 2, 2))
                if generation_response_error:
                    raise RuntimeError("Synthetic error after committing the hardware key")
                return owner.document_key.public_key()

            def attest_key(self, slot):
                return owner.leaf

            def decrypt(self, slot, ciphertext, padding):
                return b"invalid challenge" if bad_challenge else owner.document_key.decrypt(ciphertext, padding)

        connection = types.SimpleNamespace(closed=False)
        connection.close = lambda: setattr(connection, "closed", True)
        return connection, Session()

    def test_enroll_fresh_token_uses_distinct_metadata_and_certificate_absence_codes(self):
        connection, session = self.enrollment_session()
        destination = self.directory / "new-enrollment.json"
        with patch.object(piv, "_connect", return_value=(connection, session)):
            record = piv.enroll(destination, "synthetic PIN", b"synthetic management key")
        self.assertEqual(record["keyId"], self.record["keyId"])
        self.assertEqual(session.generation_calls, 1)
        self.assertEqual(session.pin_calls, 1)
        self.assertTrue(connection.closed)
        self.assertEqual(piv.load_enrollment(destination)[0], record)

    def test_enroll_occupied_slot_unknown_status_and_wrong_pin_never_generate_or_retry(self):
        for changes in [{"occupied": True}, {"wrong_missing_status": True}, {"wrong_pin": True}]:
            connection, session = self.enrollment_session(**changes)
            with patch.object(piv, "_connect", return_value=(connection, session)):
                with self.assertRaises(piv.VerificationError):
                    piv.enroll(self.directory / "not-created.json", "synthetic PIN", b"synthetic management key")
            self.assertEqual(session.generation_calls, 0)
            self.assertLessEqual(session.pin_calls, 1)
            self.assertTrue(connection.closed)
            self.assertFalse((self.directory / "not-created.json").exists())

    def test_failed_live_challenge_warns_that_generated_key_remains(self):
        connection, session = self.enrollment_session(bad_challenge=True)
        with patch.object(piv, "_connect", return_value=(connection, session)):
            with self.assertRaisesRegex(piv.VerificationError, "slot 82 now contains a generated key"):
                piv.enroll(self.directory / "not-created.json", "synthetic PIN", b"synthetic management key")
        self.assertEqual(session.generation_calls, 1)
        self.assertFalse((self.directory / "not-created.json").exists())

    def test_generation_response_failure_reports_unknown_state_and_never_retries(self):
        connection, session = self.enrollment_session(generation_response_error=True)
        with patch.object(piv, "_connect", return_value=(connection, session)):
            with self.assertRaisesRegex(piv.VerificationError, "slot 82 may now contain a generated key.*state is unknown"):
                piv.enroll(self.directory / "not-created.json", "synthetic PIN", b"synthetic management key")
        self.assertEqual(session.generation_calls, 1)
        self.assertTrue(connection.closed)
        self.assertFalse((self.directory / "not-created.json").exists())

    def test_driver_cleanup_cannot_mask_persistent_generated_key_warning(self):
        connection, session = self.enrollment_session(bad_challenge=True)
        connection.close = lambda: (_ for _ in ()).throw(RuntimeError("synthetic driver cleanup failure"))
        with patch.object(piv, "_connect", return_value=(connection, session)):
            with self.assertRaisesRegex(piv.VerificationError, "slot 82 now contains a generated key"):
                piv.enroll(self.directory / "not-created.json", "synthetic PIN", b"synthetic management key")
        self.assertEqual(session.generation_calls, 1)

    def test_noninteractive_enrollment_does_not_prompt_or_connect(self):
        with patch.object(piv.sys.stdin, "isatty", return_value=False), patch.object(piv.getpass, "getpass") as prompt, patch.object(piv, "_connect") as connect:
            self.assertEqual(piv.main(["enroll", "--output", str(self.directory / "never-created.json")]), 1)
            prompt.assert_not_called()
            connect.assert_not_called()

    def test_cli_prints_bounded_postgeneration_warning_without_prompted_secrets(self):
        message = "Enrollment did not complete; slot 82 now contains a generated key. No reset, deletion, or retry was performed."
        output = io.StringIO()
        with patch.object(piv.sys.stdin, "isatty", return_value=True), patch.object(piv.getpass, "getpass", side_effect=["synthetic secret PIN", "ab" * 24]), patch.object(piv, "enroll", side_effect=piv.VerificationError(message)), patch.object(piv.sys, "stderr", output):
            self.assertEqual(piv.main(["enroll", "--output", str(self.directory / "never-created.json")]), 1)
        self.assertEqual(output.getvalue(), message + "\n")
        self.assertNotIn("synthetic secret PIN", output.getvalue())
        self.assertNotIn("ab" * 24, output.getvalue())

    def test_official_trust_bundle_hash_pins(self):
        # Read only the repository's real trust files, not the synthetic test root.
        self.trust.stop()
        roots, intermediates = piv.load_trust_bundle()
        self.assertEqual(len(roots), 2)
        self.assertGreaterEqual(len(intermediates), 1)
        for root in roots:
            piv._dates(root)
            piv._signature(root, root)
        for intermediate in intermediates:
            piv.verify_endorsement(intermediate)
        with patch.object(piv, "TRUST_PINS", {"yubico-ca-1.pem": "0" * 64}):
            with self.assertRaises(piv.VerificationError):
                piv.load_trust_bundle()

    def test_pcsc_adapter_uses_one_exclusive_connection_without_shared_fallback(self):
        events = []

        class Card:
            def connect(self):
                events.append("exclusive-connect")

            def transmit(self, apdu):
                return [1, 2, 3], 0x90, 0x00

            def disconnect(self):
                events.append("disconnect")

            def release(self):
                events.append("release")

        card = Card()
        reader = type("Reader", (), {"__str__": lambda self: "Yubico YubiKey CCID", "createConnection": lambda self: object()})()
        system = types.ModuleType("smartcard.System")
        system.readers = lambda: [reader]
        exclusive = types.ModuleType("smartcard.ExclusiveConnectCardConnection")
        exclusive.ExclusiveConnectCardConnection = lambda underlying: card
        modules = {"smartcard": types.ModuleType("smartcard"), "smartcard.System": system, "smartcard.ExclusiveConnectCardConnection": exclusive}
        with patch.dict(sys.modules, modules), patch("yubikit.piv.PivSession", return_value="synthetic session"):
            connection, session = piv._connect()
            self.assertEqual(session, "synthetic session")
            self.assertEqual(connection.send_and_receive(b"\x00\x01"), (b"\x01\x02\x03", 0x9000))
            connection.close()
        self.assertEqual(events, ["exclusive-connect", "disconnect", "release"])
        card.connect = lambda: (_ for _ in ()).throw(RuntimeError("exclusive unavailable"))
        with patch.dict(sys.modules, modules), patch("yubikit.piv.PivSession") as session_factory:
            with self.assertRaises(piv.VerificationError):
                piv._connect()
            session_factory.assert_not_called()
        self.assertEqual(events[-2:], ["disconnect", "release"])


if __name__ == "__main__":
    unittest.main()
