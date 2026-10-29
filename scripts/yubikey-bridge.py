#!/usr/bin/env python3
"""Private, loopback-only delivery of one enrolled YubiKey-encrypted document.

This process never provisions a key, accepts caller-supplied ciphertext, reconnects
to a removed device, or repeats a PIN verification. The owner exposes the loopback
service through an independently configured authenticated HTTPS transport.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hmac
import importlib
import json
import os
import re
import secrets
import stat
import sys
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 8087
DOCUMENT_PATH = "/internal/llms.txt"
MAX_DOCUMENT_BYTES = 16 * 1024
MAX_PLAINTEXT_BYTES = 2048
TOKEN_RE = re.compile(rb"[A-Za-z0-9_-]{43}\Z")
KEY_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class BridgeError(Exception):
    """Safe, deliberately non-specific startup or delivery failure."""


def canonical_site_origin(value: str) -> str:
    """Accept an HTTPS DNS origin without credentials, ports, query, or subpath."""
    if not isinstance(value, str) or len(value) > 253:
        raise BridgeError("Invalid canonical site origin.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        labels = hostname.split(".") if hostname else []
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.netloc != hostname
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or len(labels) < 2
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
            or all(label.isdigit() for label in labels)
        ):
            raise BridgeError("Invalid canonical site origin.")
    except (ValueError, AttributeError) as error:
        raise BridgeError("Invalid canonical site origin.") from None
    return f"https://{hostname}"


def _protected_bytes(file_path: str | os.PathLike[str], limit: int) -> bytes:
    """Open and validate the inode before reading; reject links and unsafe modes."""
    descriptor = None
    try:
        before = os.lstat(file_path)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid() or before.st_nlink != 1:
            raise BridgeError("Protected file is unavailable or has unsafe permissions.")
        descriptor = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_uid != os.getuid()
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            or current.st_size > limit
        ):
            raise BridgeError("Protected file is unavailable or has unsafe permissions.")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16384))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > limit:
            raise BridgeError("Protected file is too large.")
        return content
    except BridgeError:
        raise
    except (OSError, ValueError, TypeError):
        raise BridgeError("Protected file is unavailable or has unsafe permissions.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_token(file_path: str | os.PathLike[str]) -> bytes:
    content = _protected_bytes(file_path, 44)
    if content.endswith(b"\n"):
        content = content[:-1]
    if not _canonical_token(content):
        raise BridgeError("Bridge token file is invalid.")
    return content


def _canonical_token(content: bytes) -> bool:
    if not isinstance(content, bytes) or not TOKEN_RE.fullmatch(content):
        return False
    try:
        decoded = base64.urlsafe_b64decode(content + b"=")
        return len(decoded) == 32 and hmac.compare_digest(base64.urlsafe_b64encode(decoded).rstrip(b"="), content)
    except (ValueError, binascii.Error):
        return False


def _private_token_parent(file_path: str | os.PathLike[str]) -> tuple[Path, int]:
    """Pin an owned private parent outside this checkout before token creation."""
    descriptor = None
    try:
        requested = Path(file_path)
        if not requested.is_absolute() or ".." in requested.parts or not requested.name:
            raise BridgeError("A canonical private token location outside the repository is required.")
        parent = requested.parent
        if parent.resolve(strict=True) != parent:
            raise BridgeError("A canonical private token location outside the repository is required.")
        repository = Path(__file__).resolve().parents[1]
        if repository == requested or repository in requested.parents:
            raise BridgeError("Bridge tokens must be created outside the repository.")
        before = os.lstat(parent)
        if not stat.S_ISDIR(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o700 or before.st_uid != os.getuid():
            raise BridgeError("Token parent must be a private owned directory with mode 0700.")
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        current = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(current.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o700
            or current.st_uid != os.getuid()
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise BridgeError("Token parent must be a private owned directory with mode 0700.")
        return requested, descriptor
    except BridgeError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, ValueError, TypeError):
        if descriptor is not None:
            os.close(descriptor)
        raise BridgeError("A canonical private token location outside the repository is required.") from None


def init_token(file_path: str | os.PathLike[str]) -> None:
    """Create a new independent token without returning or printing its value."""
    descriptor = None
    parent_descriptor = None
    created = False
    try:
        location, parent_descriptor = _private_token_parent(file_path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(location.name, flags, 0o600, dir_fd=parent_descriptor)
        created = True
        os.fchmod(descriptor, 0o600)
        content = secrets.token_urlsafe(32).encode("ascii") + b"\n"
        while content:
            written = os.write(descriptor, content)
            if written <= 0:
                raise BridgeError("Bridge token file could not be created.")
            content = content[written:]
        os.fsync(descriptor)
    except (OSError, ValueError, TypeError):
        raise BridgeError("Bridge token file could not be created; it must be a new private file.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        # Never overwrite an existing token; remove only a newly created incomplete file.
        if created and sys.exc_info()[0] is not None:
            try:
                os.unlink(location.name, dir_fd=parent_descriptor)
            except OSError:
                pass
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def load_document(file_path: str | os.PathLike[str], site_url: str, provider_module: Any) -> dict[str, Any]:
    raw = _protected_bytes(file_path, MAX_DOCUMENT_BYTES)
    try:
        envelope = json.loads(raw.decode("utf-8"))
        return provider_module.validate_envelope(envelope, expected_site_url=canonical_site_origin(site_url))
    except Exception:
        raise BridgeError("Encrypted document validation failed.") from None


class BridgeRuntime:
    """One token, one document, one PIN-verified SDK session; no retry/reconnect."""

    def __init__(self, provider: Any, envelope: dict[str, Any], token: bytes, key_id: str):
        if (
            not _canonical_token(token)
            or not isinstance(key_id, str)
            or not KEY_ID_RE.fullmatch(key_id)
            or not isinstance(envelope, dict)
            or envelope.get("keyId") != key_id
        ):
            raise BridgeError("Bridge session validation failed.")
        self.provider = provider
        self.envelope = envelope
        self._token = token
        self.key_id = key_id
        self.active = True

    def authenticated(self, headers: Any) -> bool:
        values = headers.get_all("Authorization", [])
        if len(values) != 1:
            return False
        try:
            candidate = values[0].encode("utf-8")
        except (UnicodeError, AttributeError):
            return False
        return hmac.compare_digest(candidate, b"Bearer " + self._token)

    def close(self) -> None:
        if self.active:
            self.active = False
            try:
                self.provider.close()
            except Exception:
                pass

    def _check(self) -> str:
        if not self.active:
            raise BridgeError("Hardware unavailable.")
        key_id = self.provider.check()
        if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id) or not hmac.compare_digest(key_id, self.key_id):
            raise BridgeError("Hardware unavailable.")
        return key_id

    def deliver(self, *, head_only: bool) -> tuple[str, bytes]:
        try:
            key_id = self._check()
            if head_only:
                return key_id, b""
            plaintext = self.provider.decrypt(self.envelope)
            if not isinstance(plaintext, bytes) or not 1 <= len(plaintext) <= MAX_PLAINTEXT_BYTES:
                raise BridgeError("Document unavailable.")
            text = plaintext.decode("utf-8")
            if any(ord(character) < 32 and character not in "\r\n\t" for character in text):
                raise BridgeError("Document unavailable.")
            return key_id, plaintext
        except Exception:
            # Device removal, failed attestation, missed touch, or decrypt failure ends
            # this session. The owner must restart and explicitly enter the PIN again.
            self.close()
            raise BridgeError("Hardware document unavailable.") from None


class PrivateBridgeServer(HTTPServer):
    allow_reuse_address = False
    request_queue_size = 4

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Socketserver's default traceback may include provider exception text.
        pass


def make_server(runtime: BridgeRuntime, *, host: str = LOOPBACK, port: int = DEFAULT_PORT) -> PrivateBridgeServer:
    if host != LOOPBACK or isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise BridgeError("The hardware bridge must bind to IPv4 loopback only.")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def log_error(self, format: str, *args: Any) -> None:
            pass

        def _reply(self, status: int, body: bytes = b"", *, key_id: str | None = None, allow: bool = False) -> None:
            self.close_connection = True
            self.send_response_only(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "private, no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("Connection", "close")
            if self.command != "HEAD":
                self.send_header("Content-Length", str(len(body)))
            if status == 401:
                self.send_header("WWW-Authenticate", 'Bearer realm="internal-llms"')
            if allow:
                self.send_header("Allow", "GET, HEAD")
            if key_id is not None and status == 200:
                self.send_header("X-Internal-LLMS-Key-ID", key_id)
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)

        def _document(self, *, head_only: bool) -> None:
            if self.path != DOCUMENT_PATH:
                self._reply(404, b"Not found.\n")
                return
            if not runtime.authenticated(self.headers):
                self._reply(401, b"Authentication required.\n")
                return
            try:
                key_id, plaintext = runtime.deliver(head_only=head_only)
            except BridgeError:
                self._reply(503, b"Hardware document unavailable.\n")
                return
            self._reply(200, plaintext, key_id=key_id)

        def do_GET(self) -> None:
            self._document(head_only=False)

        def do_HEAD(self) -> None:
            self._document(head_only=True)

        def _method_not_allowed(self) -> None:
            self._reply(405, b"Method not allowed.\n", allow=True)

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = _method_not_allowed

        def handle_expect_100(self) -> bool:
            self._reply(417, b"Request not supported.\n")
            return False

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            # Never reflect request lines, methods, header content, or exception text.
            if code == 501:
                self._method_not_allowed()
            else:
                self._reply(400, b"Invalid request.\n")

    return PrivateBridgeServer((host, port), Handler)


def _hidden_pin() -> str:
    if not sys.stdin.isatty():
        raise BridgeError("Start the bridge in an interactive terminal for its hidden PIN prompt.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            pin = getpass.getpass("YubiKey PIV PIN (hidden): ")
        if not isinstance(pin, str) or not re.fullmatch(r"[\x20-\x7e]{6,8}", pin):
            raise BridgeError("A valid hidden PIV PIN is required.")
        return pin
    except (EOFError, getpass.GetPassWarning):
        raise BridgeError("A hidden PIN prompt is required.") from None


def start_runtime(args: argparse.Namespace, *, provider_module: Any = None, prompt: Any = _hidden_pin) -> BridgeRuntime:
    token = load_token(args.token_file)
    if provider_module is None:
        provider_module = importlib.import_module("yubikey_piv")
    envelope = load_document(args.document, args.site_url, provider_module)
    provider = provider_module.Provider(args.enrollment)
    pin = None
    try:
        pin = prompt()
        provider.open(pin)  # Exactly one verification; provider owns no retained PIN.
        pin = None
        key_id = provider.check()
        if envelope.get("keyId") != key_id:
            raise BridgeError("Encrypted document does not match the enrolled hardware key.")
        return BridgeRuntime(provider, envelope, token, key_id)
    except Exception:
        try:
            provider.close()
        except Exception:
            pass
        raise BridgeError("Hardware bridge session could not be opened. No automatic PIN retry was attempted.") from None
    finally:
        pin = None


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Choose a local unprivileged port.") from None
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("Choose a local unprivileged port.")
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loopback-only YubiKey PIV document bridge; no public listener or key provisioning.")
    commands = parser.add_subparsers(dest="command", required=True)
    token_parser = commands.add_parser("init-token", help="Create a new private token file without displaying the token.")
    token_parser.add_argument("--token-file", required=True)
    serve_parser = commands.add_parser("serve", help="Open one enrolled hardware session with a hidden PIN prompt.")
    serve_parser.add_argument("--enrollment", required=True)
    serve_parser.add_argument("--document", required=True)
    serve_parser.add_argument("--token-file", required=True)
    serve_parser.add_argument("--site-url", required=True)
    serve_parser.add_argument("--port", type=_port, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    runtime = None
    server = None
    try:
        if args.command == "init-token":
            init_token(args.token_file)
            print("Private bridge token file created.")
            return 0
        args.site_url = canonical_site_origin(args.site_url)
        runtime = start_runtime(args)
        server = make_server(runtime, port=args.port)
        print(f"Private hardware bridge listening on {LOOPBACK}:{args.port}; no public listener configured.")
        server.serve_forever(poll_interval=0.5)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        print("Hardware bridge operation failed. Check protected files and enrolled hardware locally; no automatic PIN retry was attempted.", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.server_close()
        if runtime is not None:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
