"""Loopback HTTP and protected-file tests; no hardware, PIN, or network service required."""
from __future__ import annotations

import argparse
import contextlib
import http.client
import importlib.util
import io
import json
import os
import pathlib
import stat
import tempfile
import threading
import types
import unittest
from unittest import mock

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "yubikey-bridge.py"
SPEC = importlib.util.spec_from_file_location("yubikey_bridge", MODULE_PATH)
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)

TOKEN = b"A" * 43
KEY_ID = "sha256:" + "ab" * 32
SITE_URL = "https://www.dunesub.de"
PLAINTEXT = b"# DuneSub Ecosystem\nPrivate hardware-backed documentation.\n"


class FakeProvider:
    def __init__(self, enrollment=None):
        self.enrollment = enrollment
        self.opens = 0
        self.checks = 0
        self.decrypts = 0
        self.closes = 0
        self.failure = None
        self.open_failure = None
        self.key_id = KEY_ID
        self.plaintext = PLAINTEXT
        self.envelopes = []

    def open(self, pin):
        self.opens += 1
        if self.open_failure:
            raise self.open_failure
        return self

    def check(self):
        self.checks += 1
        if self.failure:
            raise self.failure
        return self.key_id

    def decrypt(self, envelope):
        self.decrypts += 1
        self.envelopes.append(envelope)
        if self.failure:
            raise self.failure
        return self.plaintext

    def close(self):
        self.closes += 1


class HttpBridgeTests(unittest.TestCase):
    def setUp(self):
        self.provider = FakeProvider()
        self.envelope = {"keyId": KEY_ID, "siteOrigin": SITE_URL, "path": "/internal/llms.txt", "ciphertext": "fixed-envelope"}
        self.runtime = bridge.BridgeRuntime(self.provider, self.envelope, TOKEN, KEY_ID)
        self.server = bridge.make_server(self.runtime, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.runtime.close()

    def request(self, method="GET", path="/internal/llms.txt", auth=True, body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        request_headers = dict(headers or {})
        if auth:
            request_headers["Authorization"] = "Bearer " + TOKEN.decode("ascii")
        try:
            client.request(method, path, body=body, headers=request_headers)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            client.close()

    def assert_private(self, headers):
        self.assertEqual(headers["Cache-Control"], "private, no-store, max-age=0")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("noindex", headers["X-Robots-Tag"])
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertFalse(any(name.lower().startswith("access-control-") for name in headers))
        self.assertNotIn("Server", headers)

    def test_authentication_precedes_device_checks_and_decryption(self):
        self.provider.failure = RuntimeError("PRIVATE_DEVICE_ERROR_PIN_TOKEN")
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                status, headers, body = self.request(method, auth=False)
                self.assertEqual(status, 401)
                self.assert_private(headers)
                self.assertNotIn(b"PRIVATE", body)
        self.assertEqual(self.provider.checks, 0)
        self.assertEqual(self.provider.decrypts, 0)
        self.assertEqual(self.provider.closes, 0)

    def test_wrong_token_or_duplicate_auth_is_rejected_before_hardware(self):
        status, _, _ = self.request(auth=False, headers={"Authorization": "Bearer " + "B" * 43})
        self.assertEqual(status, 401)
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            client.putrequest("GET", "/internal/llms.txt")
            client.putheader("Authorization", "Bearer " + TOKEN.decode())
            client.putheader("Authorization", "Bearer " + TOKEN.decode())
            client.endheaders()
            response = client.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        finally:
            client.close()
        self.assertEqual(self.provider.checks, 0)

    def test_head_verifies_current_key_without_private_operation_or_body(self):
        status, headers, body = self.request("HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Internal-LLMS-Key-ID"], KEY_ID)
        self.assertEqual(body, b"")
        self.assert_private(headers)
        self.assertEqual(self.provider.checks, 1)
        self.assertEqual(self.provider.decrypts, 0)

    def test_get_uses_only_fixed_envelope_and_returns_verified_plaintext(self):
        status, headers, body = self.request(body=b'{"ciphertext":"attacker-controlled"}')
        self.assertEqual(status, 200)
        self.assertEqual(body, PLAINTEXT)
        self.assertEqual(headers["X-Internal-LLMS-Key-ID"], KEY_ID)
        self.assert_private(headers)
        self.assertEqual(self.provider.checks, 1)
        self.assertEqual(self.provider.decrypts, 1)
        self.assertIs(self.provider.envelopes[0], self.envelope)

    def test_missing_device_returns_generic_503_and_never_reconnects(self):
        self.provider.failure = RuntimeError("PRIVATE_TOKEN_AND_PIN_IN_DRIVER_ERROR")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status, headers, body = self.request()
            second_status, _, _ = self.request("HEAD")
        self.assertEqual((status, second_status), (503, 503))
        self.assertEqual(body, b"Hardware document unavailable.\n")
        self.assert_private(headers)
        self.assertNotIn("X-Internal-LLMS-Key-ID", headers)
        self.assertEqual(self.provider.checks, 1)
        self.assertEqual(self.provider.decrypts, 0)
        self.assertEqual(self.provider.opens, 0)
        self.assertEqual(self.provider.closes, 1)
        self.assertEqual(output.getvalue(), "")

    def test_changed_key_id_fails_closed_before_decrypt(self):
        self.provider.key_id = "sha256:" + "cd" * 32
        status, _, body = self.request()
        self.assertEqual(status, 503)
        self.assertNotIn(self.provider.key_id.encode(), body)
        self.assertEqual(self.provider.decrypts, 0)
        self.assertFalse(self.runtime.active)

    def test_invalid_plaintext_is_never_returned(self):
        self.provider.plaintext = b"PRIVATE_BAD_PLAINTEXT\x00"
        status, headers, body = self.request()
        self.assertEqual(status, 503)
        self.assertNotIn(b"PRIVATE", body)
        self.assertNotIn("X-Internal-LLMS-Key-ID", headers)

    def test_plaintext_larger_than_policy_limit_is_never_returned(self):
        self.provider.plaintext = b"x" * 2049
        status, headers, body = self.request()
        self.assertEqual(status, 503)
        self.assertEqual(body, b"Hardware document unavailable.\n")
        self.assertNotIn("X-Internal-LLMS-Key-ID", headers)

    def test_other_paths_queries_encoded_paths_and_methods_never_use_hardware(self):
        for path in ("/", "/llms.txt", "/internal/llms.txt?ciphertext=evil", "/internal%2fllms.txt", "http://localhost/internal/llms.txt"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path=path)[0], 404)
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "CUSTOM"):
            with self.subTest(method=method):
                status, headers, body = self.request(method)
                self.assertEqual(status, 405)
                self.assertEqual(headers["Allow"], "GET, HEAD")
                self.assert_private(headers)
                self.assertNotIn(method.encode(), body)
        self.assertEqual(self.provider.checks, 0)
        self.assertEqual(self.provider.decrypts, 0)


class FileAndStartupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name).resolve()
        self.token_file = self.root / "bridge.token"
        self.document_file = self.root / "llms.encrypted.json"

    def tearDown(self):
        self.directory.cleanup()

    def write_protected(self, path, content):
        path.write_bytes(content)
        path.chmod(0o600)

    def test_new_token_is_random_protected_and_never_printed_or_overwritten(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(bridge.main(["init-token", "--token-file", str(self.token_file)]), 0)
        token = bridge.load_token(self.token_file)
        self.assertEqual(len(token), 43)
        self.assertRegex(token, rb"\A[A-Za-z0-9_-]{43}\Z")
        self.assertEqual(stat.S_IMODE(self.token_file.stat().st_mode), 0o600)
        self.assertNotIn(token.decode(), output.getvalue())
        self.assertIsNone(bridge.init_token(self.root / "second.token"))
        self.assertNotEqual(token, bridge.load_token(self.root / "second.token"))
        with self.assertRaises(bridge.BridgeError):
            bridge.init_token(self.token_file)
        self.assertEqual(bridge.load_token(self.token_file), token)

    def test_unsafe_permissions_symlink_hardlink_directory_owner_and_fifo_rejected(self):
        self.write_protected(self.token_file, TOKEN + b"\n")
        self.token_file.chmod(0o640)
        with self.assertRaises(bridge.BridgeError):
            bridge.load_token(self.token_file)
        self.token_file.chmod(0o600)
        link = self.root / "symlink"
        link.symlink_to(self.token_file)
        with self.assertRaises(bridge.BridgeError):
            bridge.load_token(link)
        with self.assertRaises(bridge.BridgeError):
            bridge.init_token(link)
        self.assertTrue(link.is_symlink())
        hardlink = self.root / "hardlink"
        os.link(self.token_file, hardlink)
        with self.assertRaises(bridge.BridgeError):
            bridge.load_token(self.token_file)
        hardlink.unlink()
        uid = os.getuid()
        with mock.patch.object(bridge.os, "getuid", return_value=uid + 1):
            with self.assertRaises(bridge.BridgeError):
                bridge.load_token(self.token_file)
        with self.assertRaises(bridge.BridgeError):
            bridge.load_token(self.root)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(bridge.BridgeError):
            bridge.load_token(fifo)

    def test_invalid_or_oversized_token_and_encrypted_document_are_rejected(self):
        for content in (b"x", TOKEN + b"\n\n", b"\xff" * 43, b"A" * 1000, b"A" * 42 + b"B"):
            self.write_protected(self.token_file, content)
            with self.assertRaises(bridge.BridgeError):
                bridge.load_token(self.token_file)
        module = types.SimpleNamespace(validate_envelope=mock.Mock(side_effect=AssertionError("must not validate oversized file")))
        self.write_protected(self.document_file, b"x" * (bridge.MAX_DOCUMENT_BYTES + 1))
        with self.assertRaises(bridge.BridgeError):
            bridge.load_document(self.document_file, SITE_URL, module)
        module.validate_envelope.assert_not_called()

    def test_tokens_require_canonical_base64url_for_exactly_32_bytes(self):
        self.write_protected(self.token_file, b"A" * 42 + b"E")
        self.assertEqual(bridge.load_token(self.token_file), b"A" * 42 + b"E")
        with self.assertRaises(bridge.BridgeError):
            bridge.BridgeRuntime(FakeProvider(), {"keyId": KEY_ID}, b"A" * 42 + b"B", KEY_ID)

    def test_token_creation_requires_canonical_owned_private_parent_outside_repository(self):
        self.root.chmod(0o750)
        with self.assertRaises(bridge.BridgeError):
            bridge.init_token(self.token_file)
        self.assertFalse(self.token_file.exists())
        self.root.chmod(0o700)
        with self.assertRaises(bridge.BridgeError):
            bridge.init_token("relative.token")
        alias = self.root / "alias"
        private_parent = self.root / "private"
        private_parent.mkdir(mode=0o700)
        alias.symlink_to(private_parent, target_is_directory=True)
        with self.assertRaises(bridge.BridgeError):
            bridge.init_token(alias / "bridge.token")
        self.assertFalse((private_parent / "bridge.token").exists())
        with mock.patch.object(bridge.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(bridge.BridgeError):
                bridge.init_token(self.token_file)
        repository = MODULE_PATH.parents[1]
        with tempfile.TemporaryDirectory(dir=repository) as directory:
            forbidden = pathlib.Path(directory).resolve() / "bridge.token"
            with self.assertRaises(bridge.BridgeError):
                bridge.init_token(forbidden)
            self.assertFalse(forbidden.exists())

    def test_runtime_rejects_envelope_not_bound_to_current_enrolled_key(self):
        provider = FakeProvider()
        for envelope in ({}, {"keyId": "sha256:" + "cd" * 32}, None):
            with self.subTest(envelope=envelope), self.assertRaises(bridge.BridgeError):
                bridge.BridgeRuntime(provider, envelope, TOKEN, KEY_ID)
        self.assertEqual(provider.checks, 0)
        self.assertEqual(provider.decrypts, 0)

    def test_startup_verifies_pin_once_and_fresh_hardware_without_retaining_pin(self):
        self.write_protected(self.token_file, TOKEN)
        self.write_protected(self.document_file, json.dumps({"keyId": KEY_ID, "siteOrigin": SITE_URL}).encode())
        provider = FakeProvider()
        module = types.SimpleNamespace(Provider=mock.Mock(return_value=provider), validate_envelope=mock.Mock(side_effect=lambda envelope, **_: envelope))
        prompt = mock.Mock(return_value="testpin")
        args = argparse.Namespace(token_file=str(self.token_file), document=str(self.document_file), site_url=SITE_URL, enrollment="public-enrollment.json")
        runtime = bridge.start_runtime(args, provider_module=module, prompt=prompt)
        try:
            self.assertEqual(provider.opens, 1)
            self.assertEqual(provider.checks, 1)
            self.assertEqual(provider.decrypts, 0)
            prompt.assert_called_once_with()
            module.validate_envelope.assert_called_once_with({"keyId": KEY_ID, "siteOrigin": SITE_URL}, expected_site_url=SITE_URL)
            self.assertFalse(any("pin" in name.lower() for name in vars(runtime)))
            self.assertNotIn("testpin", repr(vars(runtime)))
        finally:
            runtime.close()

    def test_wrong_pin_is_not_retried_and_error_does_not_reveal_provider_details(self):
        self.write_protected(self.token_file, TOKEN)
        self.write_protected(self.document_file, json.dumps({"keyId": KEY_ID}).encode())
        provider = FakeProvider()
        provider.open_failure = RuntimeError("PRIVATE_PIN_AND_TOKEN")
        module = types.SimpleNamespace(Provider=lambda _: provider, validate_envelope=lambda envelope, **_: envelope)
        args = argparse.Namespace(token_file=str(self.token_file), document=str(self.document_file), site_url=SITE_URL, enrollment="public.json")
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.start_runtime(args, provider_module=module, prompt=lambda: "testpin")
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertEqual(provider.opens, 1)
        self.assertEqual(provider.checks, 0)
        self.assertEqual(provider.closes, 1)

    def test_bad_token_or_document_fails_before_prompt_or_hardware(self):
        prompt = mock.Mock(side_effect=AssertionError("must not prompt"))
        module = types.SimpleNamespace(Provider=mock.Mock(side_effect=AssertionError("must not touch hardware")), validate_envelope=lambda envelope, **_: envelope)
        args = argparse.Namespace(token_file=str(self.token_file), document=str(self.document_file), site_url=SITE_URL, enrollment="public.json")
        with self.assertRaises(bridge.BridgeError):
            bridge.start_runtime(args, provider_module=module, prompt=prompt)
        self.write_protected(self.token_file, TOKEN)
        self.write_protected(self.document_file, b"not json")
        with self.assertRaises(bridge.BridgeError):
            bridge.start_runtime(args, provider_module=module, prompt=prompt)
        prompt.assert_not_called()
        module.Provider.assert_not_called()

    def test_canonical_origin_validation_rejects_credentials_subpaths_ports_or_non_https(self):
        self.assertEqual(bridge.canonical_site_origin(SITE_URL + "/"), SITE_URL)
        for value in ("http://www.dunesub.de", "https://user@www.dunesub.de", "https://www.dunesub.de:443", "https://www.dunesub.de/path", "https://www.dunesub.de?token=secret", "https://127.0.0.1", "https://localhost", "https://www.dunesub.de#fragment"):
            with self.subTest(value=value), self.assertRaises(bridge.BridgeError):
                bridge.canonical_site_origin(value)

    def test_public_bind_addresses_and_invalid_ports_are_rejected_before_listening(self):
        runtime = bridge.BridgeRuntime(FakeProvider(), {"keyId": KEY_ID}, TOKEN, KEY_ID)
        for host in ("0.0.0.0", "::", "::1", "localhost", "127.0.0.2", "192.168.0.1"):
            with self.subTest(host=host), self.assertRaises(bridge.BridgeError):
                bridge.make_server(runtime, host=host, port=0)
        for port in (-1, 65536, True, "8087"):
            with self.subTest(port=port), self.assertRaises(bridge.BridgeError):
                bridge.make_server(runtime, port=port)
        for port in ("0", "80", "65536", "not-a-port"):
            with self.subTest(port=port), self.assertRaises(argparse.ArgumentTypeError):
                bridge._port(port)

    def test_noninteractive_pin_prompt_fails_without_echoing_or_using_environment(self):
        with mock.patch.object(bridge.sys.stdin, "isatty", return_value=False), mock.patch.object(bridge.getpass, "getpass") as prompt:
            with self.assertRaises(bridge.BridgeError):
                bridge._hidden_pin()
            prompt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
