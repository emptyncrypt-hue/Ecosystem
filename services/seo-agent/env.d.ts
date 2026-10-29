/** Secret bindings are provisioned remotely; type checks never need secret values. */
interface Env {
  AGENT_TOKEN: string;
  /** Exact canonical HTTPS control-plane origin. Omit to disable passkeys. */
  AUTH_ORIGIN?: string;
  /** Independent random AES-256 key, canonical base64url; Worker secret only. */
  INTERNAL_LLMS_KEY?: string;
  /** Versioned AES-256-GCM envelope; Worker secret only, not a public resource. */
  INTERNAL_LLMS_CIPHERTEXT?: string;
  /** Explicit provider selection; absent preserves the software envelope. */
  INTERNAL_LLMS_PROVIDER?: 'software' | 'yubikey-piv';
  /** Dedicated HTTPS bridge endpoint, never the public site or this Worker. */
  INTERNAL_LLMS_BRIDGE_URL?: string;
  /** Independent bridge bearer credential, not the control-plane token. */
  INTERNAL_LLMS_BRIDGE_TOKEN?: string;
  /** Enrolled PIV public-key fingerprint; enrollment binding, not remote attestation. */
  INTERNAL_LLMS_BRIDGE_KEY_ID?: string;
  /** Comma-separated HTTPS origins whose sitemap locations map to SITE_URL. */
  SITEMAP_ORIGIN_ALIASES?: string;
  /** Explicit, verified local paths equivalent to the canonical homepage. */
  HOMEPAGE_PATH_ALIASES?: string;
  GSC_SERVICE_ACCOUNT_JSON?: string;
  GEMINI_API_KEY?: string;
  PERPLEXITY_API_KEY?: string;
  OPENAI_API_KEY?: string;
  ANTHROPIC_API_KEY?: string;
}
