#!/usr/bin/env python3
"""OEM-attested YubiKey PIV key wrapping; no software private-key fallback.

RSA operations require the enrolled token and a physical touch. The random
AES data key and plaintext exist briefly in host memory; this is not a TPM,
remote host attestation, or a claim that all document processing occurs in an HSM.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sys
import warnings
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

ROOT = Path(__file__).resolve().parent.parent
TRUST_DIRECTORY = ROOT / "config" / "yubico-piv"
TRUST_PINS = {
    "yubico-ca-1.pem": "9271d914d48d05487666703586aea27d9a69ad0c8ddf8c2fc4c8734a04285887",
    "yubico-piv-ca-1.pem": "6234f33d5f652109d265b391f2898b8ba92f62df406b684db18363f50d7c9129",
    "yubico-intermediate.pem": "ec0172fe38838e3de174aae4e058bb44920be47cebd8d658a0fba1634b82aee1",
}
SLOT = 0x82
PATH = "/internal/llms.txt"
ALGORITHM = "AES-256-GCM+RSA-OAEP-SHA256"
FIRMWARE_OID = ObjectIdentifier("1.3.6.1.4.1.41482.3.3")
POLICY_OID = ObjectIdentifier("1.3.6.1.4.1.41482.3.8")
MAX_DOCUMENT = 2048


class VerificationError(Exception):
    """A bounded, nonsecret error suitable for operator output."""


def _fail():
    raise VerificationError("YubiKey PIV verification failed; no software fallback is available.")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value, minimum, maximum):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value) or len(value) > (maximum * 4 + 2) // 3:
        _fail()
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        _fail()
    if not minimum <= len(result) <= maximum or _b64(result) != value:
        _fail()
    return result


def _spki(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _key_id(key):
    return "sha256:" + hashlib.sha256(_spki(key)).hexdigest()


def _rsa(key):
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048 or key.public_numbers().e != 65537:
        _fail()
    return key


def _origin(value):
    if not isinstance(value, str) or len(value) > 512:
        _fail()
    try:
        url = urlsplit(value)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.port not in (None, 443) or url.path not in ("", "/") or url.query or url.fragment:
            _fail()
        origin = "https://" + url.hostname.lower()
        if value not in (origin, origin + "/"):
            _fail()
        return origin
    except (ValueError, TypeError):
        _fail()


def _document(value):
    if not isinstance(value, (bytes, bytearray)) or not 1 <= len(value) <= MAX_DOCUMENT:
        _fail()
    try:
        text = bytes(value).decode("utf-8", errors="strict")
    except UnicodeError:
        _fail()
    if "\0" in text:
        _fail()
    return bytes(value)


def _read_private(path, maximum=65536):
    """Read a bounded, caller-owned regular file without following symlinks."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > maximum:
            _fail()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            _fail()
        return value
    finally:
        os.close(descriptor)


def _output_path(path):
    supplied = Path(path).expanduser()
    path = supplied.parent.resolve(strict=True) / supplied.name
    if path.is_relative_to(ROOT):
        raise VerificationError("Write private enrollment and encrypted document files outside the repository.")
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o077 or not os.access(path.parent, os.W_OK | os.X_OK):
        raise VerificationError("Use an existing private directory owned by the current user with mode 0700.")
    if path.exists() or path.is_symlink():
        raise FileExistsError("Output already exists.")
    return path


def _write_new(path, value):
    path = _output_path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "w", closefd=False, encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_trust_bundle():
    roots, intermediates = [], []
    for name, expected in TRUST_PINS.items():
        data = (TRUST_DIRECTORY / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            _fail()
        certificates = x509.load_pem_x509_certificates(data)
        if name == "yubico-intermediate.pem":
            # This OEM bundle also contains FIDO/OpenPGP/SD/HSM issuers. The
            # document provider accepts only the PIV branches and their parents.
            names = {"Yubico Attestation Intermediate A 1", "Yubico Attestation Intermediate B 1", "Yubico PIV Attestation A 1", "Yubico PIV Attestation B 1", "Yubico PIV Attestation B2 1"}
            certificates = [cert for cert in certificates if len(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 1 and cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value in names]
        (intermediates if name == "yubico-intermediate.pem" else roots).extend(certificates)
    return roots, intermediates


def _dates(cert):
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        _fail()
    # Unknown critical extensions cannot silently introduce unprocessed constraints.
    known = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE, ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    for extension in cert.extensions:
        if extension.critical and extension.oid not in known:
            _fail()


def _signature(child, issuer):
    if child.issuer != issuer.subject:
        _fail()
    algorithm = child.signature_hash_algorithm
    if algorithm is None or algorithm.digest_size < 32:
        _fail()
    key = issuer.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048:
        key.verify(child.signature, child.tbs_certificate_bytes, child.signature_algorithm_parameters or padding.PKCS1v15(), algorithm)
    elif isinstance(key, ec.EllipticCurvePublicKey) and key.key_size >= 256:
        key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(algorithm))
    else:
        _fail()


def _constraints(cert, ca_below):
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not constraints.ca or not usage.key_cert_sign or (constraints.path_length is not None and ca_below > constraints.path_length):
        _fail()


def verify_endorsement(attestation):
    """Validate the factory f9 endorsement to a locally pinned Yubico root."""
    roots, intermediates = load_trust_bundle()
    root_fingerprints = {cert.fingerprint(hashes.SHA256()) for cert in roots}
    _dates(attestation)

    def walk(cert, visited, ca_below):
        fingerprint = cert.fingerprint(hashes.SHA256())
        if fingerprint in visited or len(visited) > 5:
            return False
        if fingerprint in root_fingerprints:
            _constraints(cert, ca_below)
            _signature(cert, cert)
            return True
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        for parent in intermediates + roots:
            if cert.issuer != parent.subject:
                continue
            try:
                _dates(parent)
                _signature(cert, parent)
                below = ca_below + int(is_ca)
                _constraints(parent, below)
                if walk(parent, visited | {fingerprint}, below):
                    return True
            except Exception:
                continue
        return False

    if not walk(attestation, set(), 0):
        _fail()


def verify_attestation(leaf, attestation, public_key, firmware):
    """Yubico PIV's f9 signs key attestations; it is not a general TLS CA.

    Some factory f9 certificates are end-entity endorsements. Accept that
    vendor-specific signing relationship only for a pinned OEM-endorsed f9 and
    a leaf with the exact PIV firmware/policy extensions and expected SPKI.
    Ordinary intermediate/root certificates must meet CA/path constraints.
    """
    verify_endorsement(attestation)
    _dates(leaf)
    _signature(leaf, attestation)
    if leaf.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "YubiKey PIV Attestation 82")]):
        _fail()
    try:
        if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            _fail()
    except x509.ExtensionNotFound:
        pass
    key = _rsa(public_key)
    if not hmac.compare_digest(_spki(key), _spki(leaf.public_key())):
        _fail()
    attested_version = leaf.extensions.get_extension_for_oid(FIRMWARE_OID).value.value
    policies = leaf.extensions.get_extension_for_oid(POLICY_OID).value.value
    if len(attested_version) != 3 or tuple(attested_version) < (5, 3, 0) or tuple(attested_version) != tuple(firmware) or policies != b"\x02\x02":
        _fail()
    return _key_id(key)


ENROLLMENT_FIELDS = {"version", "provider", "slot", "keyId", "publicKeySpki", "attestationCertificate", "keyCertificate", "firmware", "pinPolicy", "touchPolicy"}


def load_enrollment(path):
    try:
        record = json.loads(_read_private(path))
        if not isinstance(record, dict) or set(record) != ENROLLMENT_FIELDS or type(record["version"]) is not int or record["version"] != 1 or record["provider"] != "yubikey-piv" or record["slot"] != "82" or record["pinPolicy"] != "ONCE" or record["touchPolicy"] != "ALWAYS":
            _fail()
        firmware = record["firmware"]
        if not isinstance(firmware, list) or len(firmware) != 3 or any(type(v) is not int or not 0 <= v <= 255 for v in firmware):
            _fail()
        key = _rsa(serialization.load_der_public_key(_decode(record["publicKeySpki"], 250, 350)))
        leaf = x509.load_pem_x509_certificate(record["keyCertificate"].encode())
        attestation = x509.load_pem_x509_certificate(record["attestationCertificate"].encode())
        key_id = verify_attestation(leaf, attestation, key, firmware)
        if record["keyId"] != key_id:
            _fail()
        return record, key
    except VerificationError:
        raise
    except Exception:
        _fail()


ENVELOPE_FIELDS = {"version", "provider", "algorithm", "keyId", "siteOrigin", "path", "wrappedKey", "nonce", "ciphertext"}


def validate_envelope(envelope, expected_site_url=None):
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS or type(envelope["version"]) is not int or envelope["version"] != 2 or envelope["provider"] != "yubikey-piv" or envelope["algorithm"] != ALGORITHM or envelope["path"] != PATH:
        _fail()
    if not isinstance(envelope["keyId"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", envelope["keyId"]):
        _fail()
    if _origin(envelope["siteOrigin"]) != envelope["siteOrigin"] or (expected_site_url is not None and _origin(expected_site_url) != envelope["siteOrigin"]):
        _fail()
    _decode(envelope["wrappedKey"], 256, 256)
    _decode(envelope["nonce"], 12, 12)
    _decode(envelope["ciphertext"], 17, MAX_DOCUMENT + 16)
    return envelope.copy()


def _aad(envelope):
    return f"dunesub-internal-llms:v2\n{envelope['siteOrigin']}\n{PATH}\n{envelope['keyId']}".encode()


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"dunesub-internal-llms:v2")


def seal(enrollment_path, plaintext, site_url):
    record, public_key = load_enrollment(enrollment_path)
    value = _document(plaintext)
    data_key = bytearray(os.urandom(32))
    try:
        envelope = {"version": 2, "provider": "yubikey-piv", "algorithm": ALGORITHM, "keyId": record["keyId"], "siteOrigin": _origin(site_url), "path": PATH}
        nonce = os.urandom(12)
        envelope.update(wrappedKey=_b64(public_key.encrypt(bytes(data_key), _oaep())), nonce=_b64(nonce), ciphertext=_b64(AESGCM(bytes(data_key)).encrypt(nonce, value, _aad(envelope))))
        return envelope
    finally:
        data_key[:] = b"\0" * len(data_key)


def _connect():
    # Lazy imports keep pure cryptographic tests usable without a PC/SC driver.
    try:
        from smartcard.System import readers
        from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
        from yubikit.core import TRANSPORT
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.piv import PivSession
        devices = [reader for reader in readers() if "yubico yubikey" in str(reader).lower()]
        if len(devices) != 1:
            raise VerificationError("Connect exactly one compatible YubiKey with PIV enabled.")
        # Unlike ykman's high-level discovery, do not silently fall back to a
        # shared connection, kill another smart-card agent, or retry a failure.
        card = ExclusiveConnectCardConnection(devices[0].createConnection())
        try:
            card.connect()
        except Exception:
            try:
                card.disconnect()
            except Exception:
                pass
            if hasattr(card, "release"):
                try:
                    card.release()
                except Exception:
                    pass
            raise

        class Connection(SmartCardConnection):
            @property
            def transport(self):
                return TRANSPORT.USB

            def send_and_receive(self, apdu):
                data, sw1, sw2 = card.transmit(list(apdu))
                return bytes(data), sw1 << 8 | sw2

            def close(self):
                try:
                    card.disconnect()
                finally:
                    if hasattr(card, "release"):
                        card.release()

        connection = Connection()
        try:
            return connection, PivSession(connection)
        except Exception:
            connection.close()
            raise
    except VerificationError:
        raise
    except Exception:
        raise VerificationError("YubiKey PIV is unavailable; install the pinned SDK and enable smart-card access.") from None


class Provider:
    def __init__(self, enrollment_path):
        self.record, self.public_key = load_enrollment(enrollment_path)
        self.connection = None
        self.session = None
        self.unlocked = False
        self.failed = False

    def _connected(self):
        if self.failed:
            _fail()
        if self.session is None:
            self.connection, self.session = _connect()
        return self.session

    def check(self):
        try:
            session = self._connected()
            if tuple(session.version) < (5, 3, 0):
                _fail()
            metadata = session.get_slot_metadata(SLOT)
            if int(metadata.key_type) != 0x07 or int(metadata.pin_policy) != 2 or int(metadata.touch_policy) != 2 or metadata.generated is not True:
                _fail()
            attestation = session.get_certificate(0xF9)
            if attestation.fingerprint(hashes.SHA256()) != x509.load_pem_x509_certificate(self.record["attestationCertificate"].encode()).fingerprint(hashes.SHA256()):
                _fail()
            key_id = verify_attestation(session.attest_key(SLOT), attestation, metadata.public_key, session.version)
            if key_id != self.record["keyId"]:
                _fail()
            return key_id
        except Exception:
            self.close()
            self.failed = True
            _fail()

    def open(self, pin):
        self.check()
        if self.unlocked:
            raise VerificationError("PIV session is already unlocked; PIN verification is not repeated.")
        try:
            self.session.verify_pin(pin)
            self.unlocked = True
            return self
        except Exception:
            self.close()
            self.failed = True
            raise VerificationError("PIV PIN verification failed; no automatic retry was attempted.") from None

    def decrypt(self, envelope, pin=None):
        data_key = None
        try:
            envelope = validate_envelope(envelope)
            if envelope["keyId"] != self.record["keyId"]:
                _fail()
            if pin is not None:
                self.open(pin)
            if not self.unlocked:
                _fail()
            self.check()
            # Every hardware private operation requires a new physical touch.
            data_key = bytearray(self.session.decrypt(SLOT, _decode(envelope["wrappedKey"], 256, 256), _oaep()))
            if len(data_key) != 32:
                _fail()
            plaintext = AESGCM(bytes(data_key)).decrypt(_decode(envelope["nonce"], 12, 12), _decode(envelope["ciphertext"], 17, MAX_DOCUMENT + 16), _aad(envelope))
            return _document(plaintext)
        except Exception:
            self.close()
            self.failed = True
            _fail()
        finally:
            if data_key is not None:
                data_key[:] = b"\0" * len(data_key)

    def close(self):
        if self.connection is not None:
            try:
                self.connection.close()
            except Exception:
                pass
        self.connection = self.session = None
        self.unlocked = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def enroll(output_path, pin, management_key):
    output_path = _output_path(output_path)
    connection, session = _connect()
    generated = False
    generation_attempted = False
    try:
        from yubikit.core.smartcard import ApduError, SW
        from yubikit.piv import KEY_TYPE, PIN_POLICY, TOUCH_POLICY
        if tuple(session.version) < (5, 3, 0):
            _fail()
        # Only an explicit absent-object APDU permits generation. Any other
        # failure is fatal; metadata/certificate presence forbids overwriting.
        for lookup, absent_status in ((session.get_slot_metadata, SW.REFERENCE_DATA_NOT_FOUND), (session.get_certificate, SW.FILE_NOT_FOUND)):
            try:
                lookup(SLOT)
            except ApduError as error:
                if error.sw != absent_status:
                    raise
            else:
                raise VerificationError("PIV slot 82 is occupied; enrollment will not replace any key or certificate.")
        attestation = session.get_certificate(0xF9)
        verify_endorsement(attestation)
        session.authenticate(management_key)
        session.verify_pin(pin)  # Exactly one attempt; never try defaults or retry.
        # An APDU timeout or SDK response-parse failure can follow a successful
        # hardware mutation. An exception must never imply that retry is safe.
        generation_attempted = True
        public_key = session.generate_key(SLOT, KEY_TYPE.RSA2048, PIN_POLICY.ONCE, TOUCH_POLICY.ALWAYS)
        generated = True
        metadata = session.get_slot_metadata(SLOT)
        if not metadata.generated or int(metadata.pin_policy) != 2 or int(metadata.touch_policy) != 2 or _spki(metadata.public_key) != _spki(public_key):
            _fail()
        leaf = session.attest_key(SLOT)
        key_id = verify_attestation(leaf, attestation, public_key, session.version)
        # A fresh challenge proves possession of the enrolled private key now.
        challenge = os.urandom(32)
        if not hmac.compare_digest(session.decrypt(SLOT, public_key.encrypt(challenge, _oaep()), _oaep()), challenge):
            _fail()
        record = {"version": 1, "provider": "yubikey-piv", "slot": "82", "keyId": key_id, "publicKeySpki": _b64(_spki(public_key)), "attestationCertificate": attestation.public_bytes(serialization.Encoding.PEM).decode(), "keyCertificate": leaf.public_bytes(serialization.Encoding.PEM).decode(), "firmware": list(session.version), "pinPolicy": "ONCE", "touchPolicy": "ALWAYS"}
        _write_new(output_path, record)
        return record
    except Exception as error:
        if generated:
            raise VerificationError("Enrollment did not complete; slot 82 now contains a generated key. No reset, deletion, or retry was performed.") from None
        if generation_attempted:
            raise VerificationError("Key generation was attempted; slot 82 may now contain a generated key. Its state is unknown. No reset, deletion, or retry was performed.") from None
        if isinstance(error, VerificationError):
            raise
        raise VerificationError("Enrollment failed before key generation; no automatic credential retry was attempted.") from None
    finally:
        try:
            connection.close()
        except Exception:
            # A driver cleanup error must not replace a bounded mutation-state
            # warning or turn a persisted enrollment into an apparent failure.
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("probe", help="Check local smart-card availability; does not enroll or claim attestation")
    enrollment = sub.add_parser("enroll", help="Create an OEM-attested key only in an empty PIV slot 82")
    enrollment.add_argument("--output", required=True)
    sealing = sub.add_parser("seal", help="Encrypt a curated UTF-8 document using an enrolled public key")
    sealing.add_argument("--enrollment", required=True)
    sealing.add_argument("--site-url", required=True)
    sealing.add_argument("--input", required=True)
    sealing.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "probe":
            connection, session = _connect()
            try:
                if tuple(session.version) < (5, 3, 0):
                    _fail()
                verify_endorsement(session.get_certificate(0xF9))
                print("PIV available; factory certificate chain validates. Private-key possession is not proven and no document key has been enrolled or activated.")
            finally:
                try:
                    connection.close()
                except Exception:
                    pass
        elif args.command == "enroll":
            _output_path(args.output)
            if not sys.stdin.isatty():
                raise VerificationError("Enrollment requires an interactive terminal with hidden credential input.")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                pin = getpass.getpass("Current PIV PIN (one attempt): ")
                management = getpass.getpass("Current PIV management key, hexadecimal (one attempt): ")
            if not re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})", management):
                raise VerificationError("Management key must be 16, 24, or 32 bytes encoded as hexadecimal.")
            record = enroll(args.output, pin, bytes.fromhex(management))
            pin = management = None
            print("Enrolled OEM-attested hardware key " + record["keyId"])
        elif args.command == "seal":
            envelope = seal(args.enrollment, _read_private(args.input, MAX_DOCUMENT), args.site_url)
            _write_new(args.output, envelope)
            print("Encrypted document written; hardware private key was not exported.")
        return 0
    except VerificationError as error:
        # Only our bounded operator errors are printable. SDK/OS exceptions may
        # contain sensitive values and are never interpolated into CLI output.
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, getpass.GetPassWarning):
        print("Operation unavailable. Check device, current credentials, pinned trust, private file permissions, and empty slot 82. No automatic retry or software fallback.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
