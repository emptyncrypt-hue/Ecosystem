# YubiKey PIV protection for internal context

This optional host provider protects the internal context encryption key with a YubiKey connected to an operator's Mac. It does not require a TPM driver. A YubiKey is a security token; this integration does not certify it as a general-purpose HSM or attest macOS itself. The existing Cloudflare software provider remains available as a separate, explicitly selected mode.

## Supported device and trust checks

Use a PIV-capable YubiKey with firmware 5.3 or later, its factory attestation credential intact, and USB smart-card/CCID access enabled. FIDO-only Security Key models, absent PIV applications, older firmware, unavailable metadata, imported keys, preview roots, and substituted attestation credentials fail verification. A USB product name alone never counts as hardware verification.

The provider uses Yubico's pinned Python SDK and an RSA-2048 key generated in the dedicated retired PIV slot **82**. Enrollment refuses an occupied slot and never resets PIV, overwrites an existing key, imports a private key, changes the PIN/PUK/management key, or modifies the factory attestation slot f9. Enrollment is an explicit local command that creates one persistent key. Treat that key as an encryption recovery dependency; losing it makes its encrypted documents unrecoverable.

[Yubico's attestation specification](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html) describes the certificate evidence for on-device generation and the firmware and PIN/touch policy extensions. This provider checks the pinned manufacturer chain, certificate signatures and validity, expected slot, generated-key metadata, public-key agreement, firmware, PIN-once policy and touch-always policy. It also performs a random hardware unwrap challenge during enrollment. Published legacy and 2025 attestation roots and intermediate candidates are pinned under `config/yubico-piv`; no runtime root downloads or arbitrary additional trust roots are accepted.

Attestation certificates contain device identifiers. Enrollment records stay in owner-only local storage and must not be committed, published, or pasted into a public issue. The bridge exposes only the enrolled public-key SHA-256 fingerprint.

## Encryption and operating boundary

Each document gets a fresh random 32-byte AES key and 12-byte nonce. AES-256-GCM authenticates the document and its site origin, private path, provider version and enrolled key fingerprint. The AES key is wrapped with the attested RSA public key using OAEP with SHA-256; only the YubiKey private operation unwraps it. The private RSA key stays on the token. AES encryption/decryption and plaintext handling occur in host memory, not inside the YubiKey. Python does not guarantee erasure of all copies from process memory.

The host serves one fixed encrypted document. It accepts no caller-supplied ciphertext, arbitrary paths, or key operations over HTTP. The loopback bridge authenticates an independent random bearer credential before hardware access. Its `HEAD` checks fresh slot metadata and attestation evidence from the open session without invoking the private key; it does not perform a fresh private-key possession challenge. `GET` additionally requires a physical touch to unwrap the document key. The PIN is entered once through a hidden terminal prompt when opening the bridge session, then is not stored or retried automatically. Removal or session failure requires restarting and unlocking the bridge.

The bridge defaults to `http://127.0.0.1:8087` and accepts only exact `GET`/`HEAD /internal/llms.txt` requests without a query string. `serve --port` can select another unprivileged port (1024–65535), but the listener always binds to `127.0.0.1`. To reach it from Cloudflare, the owner must provision a dedicated HTTPS hostname through a protected tunnel or equivalent authenticated TLS gateway. Do not expose the loopback service directly or forward the dashboard token to it. The bridge's bearer credential is required even when the gateway adds another identity layer. If the gateway requires service credentials, its client integration must be configured separately; the Worker currently sends the bridge bearer credential only.

The Worker trusts the configured HTTPS bridge and checks its enrolled-key fingerprint header. That header binds a configured service to an enrollment; it is **not** a remote attestation of the Mac, proof of a physical touch, or protection against a compromised host. Both the Mac and Cloudflare handle the authorized plaintext response. No hardware key, wrapped document, bridge credential, or plaintext is placed in the public injector, shared KV, D1, AI drafts, or sitemap.

## Mac enrollment

Run these steps on the Mac where the YubiKey is connected, from this repository checkout. Use Node.js 24+ for the complete deployment workflow and Python 3.12 for the host provider. The read-only discovery probe alone also supports Node.js 22.8+. Install Python and YubiKey Manager from their official distributions if absent. The Yubico SDK uses macOS smart-card support; some installations may require Apple's existing command-line build tools to build its Python dependency. No local hardware is visible from a remote cloud checkout.

First run the non-mutating discovery check:

```sh
node scripts/hardware-security-probe.mjs --expected-platform macos
```

The output deliberately reports hardware as unverified even if it sees a YubiKey. It omits serial numbers and personal USB labels. Then prepare owner-only storage outside the repository and an isolated Python environment:

```sh
install -d -m 700 "$HOME/.local/share/dunesub-piv"
python3.12 -m venv "$HOME/.local/share/dunesub-piv/venv"
"$HOME/.local/share/dunesub-piv/venv/bin/python" -m pip install -r requirements-yubikey.txt
```

Use your existing PIV PIN and management credential from your secret manager. Prepare these using Yubico's supported management tools if the device has never been provisioned; do not reset or reconfigure a token containing credentials you need. No PIN, PUK, management key, or bridge token belongs in a command argument, source file, chat message, or CI log.

Check the PIV device, then explicitly enroll the unused slot. Follow the hidden prompts and touch the token when requested:

```sh
"$HOME/.local/share/dunesub-piv/venv/bin/python" scripts/yubikey_piv.py probe
"$HOME/.local/share/dunesub-piv/venv/bin/python" scripts/yubikey_piv.py enroll \
  --output "$HOME/.local/share/dunesub-piv/enrollment.json"
```

Prepare an approved 1–2,048-byte UTF-8 document in protected storage outside the checkout, excluding credentials and confidential archives. The input must be a regular, current-user-owned file with one link and mode `0600`; symlinks and shared permissions are rejected. For the approved input shown below, run `chmod 600 "$HOME/.local/share/dunesub-piv/llms.txt"` before sealing. Seal it locally; this command does not need the RSA private key and never prints the document or AES key:

```sh
"$HOME/.local/share/dunesub-piv/venv/bin/python" scripts/yubikey_piv.py seal \
  --enrollment "$HOME/.local/share/dunesub-piv/enrollment.json" \
  --site-url https://www.dunesub.de \
  --input "$HOME/.local/share/dunesub-piv/llms.txt" \
  --output "$HOME/.local/share/dunesub-piv/llms.enc.json"
```

Retain the original approved document only under your normal restricted storage/retention policy. Create a distinct bridge credential and start the host service:

```sh
"$HOME/.local/share/dunesub-piv/venv/bin/python" scripts/yubikey-bridge.py init-token \
  --token-file "$HOME/.local/share/dunesub-piv/bridge.token"
"$HOME/.local/share/dunesub-piv/venv/bin/python" scripts/yubikey-bridge.py serve \
  --enrollment "$HOME/.local/share/dunesub-piv/enrollment.json" \
  --document "$HOME/.local/share/dunesub-piv/llms.enc.json" \
  --token-file "$HOME/.local/share/dunesub-piv/bridge.token" \
  --site-url https://www.dunesub.de
```

The token file is created exclusively with mode `0600`; its value is never printed. Supply it to the deployment secret manager through a protected file/import mechanism. The host must stay awake and connected, and a person must touch the YubiKey within the Worker's ten-second request deadline. This is an attended integration, not an unattended always-available cloud HSM.

## Worker configuration and activation

After enrollment and the dedicated HTTPS bridge are verified, set this complete group of control Worker deployment secrets:

| Secret | Value |
| --- | --- |
| `INTERNAL_LLMS_PROVIDER` | `yubikey-piv` |
| `INTERNAL_LLMS_BRIDGE_URL` | Dedicated canonical HTTPS DNS URL ending exactly `/internal/llms.txt` |
| `INTERNAL_LLMS_BRIDGE_TOKEN` | Independent canonical base64url encoding of 32 random bytes from `init-token` |
| `INTERNAL_LLMS_BRIDGE_KEY_ID` | `sha256:` followed by the enrolled public-key fingerprint, 64 lowercase hex characters |

Do not supply `INTERNAL_LLMS_KEY` or `INTERNAL_LLMS_CIPHERTEXT` in this deployment. The normal `AGENT_TOKEN` and `CLOUDFLARE_API_TOKEN` remain independent secrets. `npm run seo:deploy` validates the complete provider group before deployment effects and sends it atomically with the control Worker secrets. A dedicated DNS hostname is required; credentials, ports, query strings, fragments, IP literals, local names and the public site hostname are rejected.

Selected `yubikey-piv` mode never reads the software encryption pair. Missing hardware, invalid attestation, wrong fingerprint, an unavailable bridge, a denied touch, expired timeout, malformed document or unknown provider results in a private generic `503`, with no software fallback. An ordinary deployment with every optional internal-context setting absent preserves the deployed provider configuration.

Wrangler retains omitted remote secrets. After verifying a hardware-mode authenticated `GET` and `HEAD`, remove the obsolete `INTERNAL_LLMS_KEY` and `INTERNAL_LLMS_CIPHERTEXT` bindings through the Cloudflare secret manager. They are ignored in hardware mode but should not remain available as unused credentials. Returning to software mode requires a deliberate deployment of a freshly sealed software key/envelope pair; it is not automatic.

Check unauthenticated access remains `401`, public context paths remain `404`, and an authenticated read fails `503` when the host is unavailable. Do not save decrypted verification output in logs. Activation is complete only after a real on-device enrollment, live unwrap and authenticated HTTPS read succeed. Unit tests and manufacturer root certificates alone cannot prove that a plugged-in device is present.

## Verification

Run `npm run check`, `npm run seo:verify`, and the optional provider tests:

```sh
"$HOME/.local/share/dunesub-piv/venv/bin/python" -m unittest discover -s test -p 'test_yubikey*.py' -v
```

These tests use synthetic certificate hierarchies and fake hardware sessions for rejection and encryption coverage; they do not attest a physical device. CI installs the pinned host dependencies and exercises the provider and HTTP bridge. The native Worker check verifies real workerd HTTP/authentication behavior with a synthetic bridge and no external service calls.
