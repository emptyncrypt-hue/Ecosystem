# Internal llms.txt

DuneSub's internal context document is available only at the SEO control Worker's exact `/internal/llms.txt` route. The deployed control hostname is `dunesub-seo-agent.plamen-r-mihaylov.workers.dev`. The route accepts authenticated HTTPS `GET` and `HEAD` requests with the existing `AGENT_TOKEN`; other methods are rejected. An authorized `HEAD` returns no document body.

“Internal” means restricted to authenticated control-plane clients. This endpoint uses an Internet-reachable Cloudflare Worker; this change does not establish a private network, VPN, Cloudflare Access application, or new identity provider.

## Software provider encryption and storage boundary

The default `software` provider encrypts the document with AES-256-GCM using an independent random 32-byte key, a fresh random 12-byte nonce for every encryption, and a 128-bit authentication tag. Its authenticated additional data binds the version, configured HTTPS site origin, and exact private route:

```text
dunesub-internal-llms:v1
https://www.dunesub.de
/internal/llms.txt
```

Two separate Cloudflare Worker secret bindings hold the key and encrypted envelope: `INTERNAL_LLMS_KEY` and `INTERNAL_LLMS_CIPHERTEXT`. They belong only to the control Worker. Neither binding is a Wrangler plaintext variable, a source file, a public injector binding, shared overrides KV, a D1 proposal, or an AI queue message. The key is independent of both API credentials. The plaintext is limited to 2,048 UTF-8 bytes, and the serialized envelope is limited to 4,096 bytes.

The envelope contains only `version`, `algorithm`, `nonce`, and `ciphertext`. Version 1 uses canonical, unpadded base64url for the key, nonce, and authenticated ciphertext. Missing configuration, incorrect keys, malformed or altered envelopes, invalid text, and context mismatches fail closed with a generic error. The document is decrypted only for an authenticated HTTPS read; plaintext exists in request memory and the authorized HTTPS response.

Cloudflare manages the software provider secret bindings. This mode makes no TPM, HSM, PKCS#11, hardware attestation, or customer-managed KMS claim. The optional [YubiKey PIV host provider](yubikey-piv.md) protects a document key with an attested on-device RSA key and an authenticated Mac bridge. It must be explicitly selected after real device enrollment; hardware mode never falls back to this software pair. The repository's Google Cloud CMEK Terraform applies to the Google services it configures; it does not configure Cloudflare encryption. Archived cryptographic reports are historical source material, not proof of runtime enforcement.

## Access and publication boundary

Every private response, including authentication and configuration errors, uses private/no-store caching, `Vary: Authorization`, `X-Robots-Tag: noindex, nofollow, noarchive`, and `X-Content-Type-Options: nosniff`. No cross-origin read permission is added. These headers supplement authentication; a robots directive does not grant or enforce access.

The public site denies `/llms.txt`, `/llms-full.txt`, and `/internal/llms.txt`, including recognized encoded and normalized variants, before reading overrides or contacting Squarespace. It returns a clean `404`, with no document, ciphertext, key, or reflected credentials. These files are not linked from public metadata or the sitemap.

The public crawler still reports missing optional `/llms.txt` as informational. A private authenticated document is not a public discovery file and does not resolve that finding. The internal document is not sent automatically to the drafting model or any external LLM.

## Provisioning and updates

The encryption helper in `scripts/internal-llms.mjs` seals a curated document in memory. Prepare content from verified public project facts and explicit operator guidance; exclude tokens, personal details, confidential archives, and unsupported infrastructure claims. Supply the key and envelope together as the two optional secret environment bindings when deploying the control Worker. The deployment selects `INTERNAL_LLMS_PROVIDER=software` with that pair; absence of the provider binding retains legacy software behavior. Hardware bridge secrets form a separate complete group, described in the YubiKey guide. Invalid or partial configuration fails before remote deployment effects.

Deployment sends `AGENT_TOKEN` and a supplied internal context pair in the same Worker upload. Its transient secrets file is outside the repository, restricted to its owner, and removed after the command. Credential values are not printed or passed as command-line arguments. Ordinary deployments that omit every optional internal-context setting retain the existing remote provider and secret bindings. Provisioning, publication, and failed mutations are not automatically retried.

For an update or rotation, seal the complete approved document with a fresh nonce and deploy a matching key/envelope pair atomically. Verify the authenticated response and public denials after deployment. Retain keys only in an appropriate secret manager; never commit them or copy decrypted output into logs or synchronization bundles.

## Verification

Tests cover authorization before decryption, HTTPS enforcement, GET/HEAD and unsupported methods, authenticated encryption and context binding, tampering and malformed data, bounded text, private response headers, and public route denial without origin or KV access. Native Cloudflare runtime tests exercise actual cryptography and HTTP behavior with synthetic data and no outbound requests. The vendored provenance manifest records the integration patch separately from the original upstream hashes.
