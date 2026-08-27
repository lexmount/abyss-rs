//! Destination-based mapping to the existing public LLM provider variants.

use abyss_plugin_protocol::event::LlmProvider;

use crate::protocol::LlmProtocol;

/// Resolves first-party hosts and preserves compatible gateway identities.
pub struct ProviderResolver;

impl ProviderResolver {
    pub fn resolve(host: &str, _protocol: LlmProtocol) -> LlmProvider {
        let host = host
            .split(':')
            .next()
            .unwrap_or(host)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host == "openai.com"
            || host.ends_with(".openai.com")
            || host == "chatgpt.com"
            || host.ends_with(".chatgpt.com")
        {
            return LlmProvider::OpenAi;
        }
        if host == "anthropic.com"
            || host.ends_with(".anthropic.com")
            || host == "claude.ai"
            || host.ends_with(".claude.ai")
        {
            return LlmProvider::Anthropic;
        }
        LlmProvider::Other(host)
    }
}
