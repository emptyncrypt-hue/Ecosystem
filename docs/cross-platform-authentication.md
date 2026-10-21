# Dashboard authentication on iOS, Android and Windows

The SEO control dashboard supports WebAuthn passkeys at `https://dunesub-seo-agent.plamen-r-mihaylov.workers.dev/dashboard`. A passkey uses the device or password manager's verification prompt. The server receives a public-key assertion; it receives no biometric template, device PIN or passkey private key.

| Platform | Sign-in options |
| --- | --- |
| iOS / iPadOS | A current Safari or other browser with passkey support, using Face ID, Touch ID, device verification or a supported security key |
| Android | A current browser with passkey support, using Android device verification, a passkey provider or a supported security key |
| Windows | A current Edge or Chrome browser, using Windows Hello, a passkey provider or a supported security key |
| macOS | A current browser with passkey support, using Touch ID, device verification, a passkey provider or a supported security key |

The browser chooses compatible authenticators. The application does not gate users by operating-system labels or require one authenticator attachment. Compatible YubiKey FIDO2 credentials work through the browser. Availability of USB, NFC, synced credentials and cross-device sign-in depends on the browser, token and passkey provider.

Platform documentation: [Apple passkeys](https://developer.apple.com/passkeys/), [Android and Chrome support](https://developers.google.com/identity/passkeys/supported-environments), [Windows passkeys](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/). The integration accepts both ES256 and RS256 credentials and requires user verification. No particular device's hardware provenance is asserted from its user-entered name or a successful passkey login.

## Deployment

The non-secret `authOrigin` in `config/seo-agent.json` enables the feature and generates the control-only `AUTH_ORIGIN` binding. It must be the exact canonical HTTPS control Worker origin, without a trailing slash, port, credentials, query or fragment. Deployment checks it against the account's discovered Worker URL before changing files or remote resources. The RP ID is the exact configured hostname; arbitrary Host headers and parent domains cannot expand the credential's scope.

The normal `npm run seo:deploy` workflow applies the idempotent D1 schema before publishing. Three additive tables store passkey public keys and labels, short-lived challenges and hashed session tokens. Existing application tables and approvals remain intact. The server library is pinned to `@simplewebauthn/server` 13.3.3 in the service lockfile; verification uses the real Cloudflare runtime.

An installation that intentionally omits `authOrigin` keeps the existing bearer API and permits dashboard token use in page memory only. Configured authentication with unavailable tables or invalid configuration fails closed. Token automation continues to work independently. Use the PR branch containing this feature for local verification; production availability begins after that revision is deployed.

## First enrollment

1. Open the exact HTTPS control dashboard in a supported browser. Keep the administrator `AGENT_TOKEN` in your secret manager.
2. Choose **Continue with token** and enter that token once. The server exchanges it for an eight-hour, secure HttpOnly session cookie.
3. Choose **Set up a passkey**, enter the administrator token in the protected field, optionally name the passkey, and choose **Create a passkey**.
4. Complete the device's verification prompt. The browser or passkey provider stores the private credential. Sign out, then test **Use a passkey**.

Repeat enrollment on another device when it needs a separate credential. A synced passkey may also be available through its provider; the server does not control provider synchronization. Keep the administrator token available as the recovery method. Enrollment and revocation require that token even when a passkey session is active; a browser session cannot add a new administrator credential by itself.

To remove a lost device's credential, open **Set up a passkey**, enter the administrator token, and choose **Revoke** next to that credential. Its existing passkey sessions are invalidated. Sign-out revokes the current session in D1 and clears its cookies. Rotating `AGENT_TOKEN` or changing the authentication origin invalidates all previous passkeys, pending challenges and sessions, so enroll replacement credentials after rotation.

## Session and request controls

Sessions are random 32-byte tokens. Only their SHA-256 hashes are stored in D1; browser cookies use the `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no Domain, and a fixed eight-hour expiry. Credentials and sessions are never written to localStorage or sessionStorage. The dashboard removes its legacy stored token on startup and clears credential fields and rendered data on sign-out.

Passkey registration and login use single-use, five-minute challenges bound to the owner, configured origin, ceremony purpose and browser challenge cookie. D1 consumes each challenge atomically before verification. The server validates the signed challenge, exact origin and RP ID, user handle, user-presence/verification flags and credential signature. Framed/cross-origin ceremonies are rejected. Zero counters are supported for synced passkeys; counter/revision updates and session issuance use a conditional transaction to reject stale or revoked credentials.

Cookie-authorized dashboard mutations require the exact Origin, a custom `X-SEO-CSRF: 1` header and JSON content type. Authentication requests have bounded bodies and read deadlines. Replies use private/no-store caching with no cross-origin access grant. Login options expose no registered credential list. Enrollment is capped at 20 active owner credentials; pending challenges at 64 and sessions at 128. Pending challenge exhaustion produces an error; operators can additionally apply their normal Cloudflare authentication-route rate policy.

Passkey sessions authorize the dashboard's explicit SEO REST operations, including its existing approval and rollback controls. MCP clients and `/internal/llms.txt` continue to require `AGENT_TOKEN`. The separate YubiKey PIV bridge protects document-key unwrapping according to [its enrollment guide](yubikey-piv.md); a dashboard passkey does not unlock that encryption key.

## Verification

With Node.js 24, run:

```sh
npm run seo:install
npm run seo:verify
```

The pipeline includes browser behavior tests and a real workerd/D1 authentication suite. The native suite uses independently generated P-256 and RSA test credentials, verifies actual signatures, and tests challenge replay, expiry, origin and UV failures, concurrent verification, revocation, token rotation, CSRF and private-route isolation. It makes no external requests. These checks exercise the standard browser protocol; an attended sign-in on each physical device remains the final compatibility check after deployment.
