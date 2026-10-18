/** Secret bindings are provisioned remotely; type checks never need secret values. */
interface Env {
  AGENT_TOKEN: string;
  /** Comma-separated HTTPS origins whose sitemap locations map to SITE_URL. */
  SITEMAP_ORIGIN_ALIASES?: string;
  GSC_SERVICE_ACCOUNT_JSON?: string;
  GEMINI_API_KEY?: string;
  PERPLEXITY_API_KEY?: string;
  OPENAI_API_KEY?: string;
  ANTHROPIC_API_KEY?: string;
}
