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
        if host == "api.deepseek.com" {
            return LlmProvider::DeepSeek;
        }
        LlmProvider::Other(host)
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderResolver;
    use crate::protocol::{AnthropicProtocol, LlmProtocol, OpenAiProtocol};
    use abyss_plugin_protocol::event::LlmProvider;

    #[test]
    fn deepseek_identity_depends_on_the_official_host_not_the_protocol() {
        for protocol in [
            LlmProtocol::OpenAi(OpenAiProtocol::Responses),
            LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions),
            LlmProtocol::Anthropic(AnthropicProtocol::Messages),
        ] {
            for host in ["api.deepseek.com", "API.DEEPSEEK.COM.:443"] {
                assert_eq!(
                    ProviderResolver::resolve(host, protocol),
                    LlmProvider::DeepSeek
                );
            }
            for host in [
                "gateway.example",
                "chat.deepseek.com",
                "api.deepseek.com.example",
                "other-api.deepseek.com",
            ] {
                assert_eq!(
                    ProviderResolver::resolve(host, protocol),
                    LlmProvider::Other(host.to_owned())
                );
            }
        }
    }
}
