/** Secret bindings are provisioned remotely; type checks never need secret values. */
interface Env {
  AGENT_TOKEN: string;
  /** Independent random AES-256 key, canonical base64url; Worker secret only. */
  INTERNAL_LLMS_KEY?: string;
  /** Versioned AES-256-GCM envelope; Worker secret only, not a public resource. */
  INTERNAL_LLMS_CIPHERTEXT?: string;
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
