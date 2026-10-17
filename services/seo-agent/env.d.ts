/** Secret bindings are provisioned remotely; type checks never need secret values. */
interface Env {
  AGENT_TOKEN: string;
  GSC_SERVICE_ACCOUNT_JSON?: string;
  GEMINI_API_KEY?: string;
  PERPLEXITY_API_KEY?: string;
  OPENAI_API_KEY?: string;
  ANTHROPIC_API_KEY?: string;
}
