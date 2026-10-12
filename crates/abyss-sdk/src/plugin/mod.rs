//! Public broker plugin runtime and protocol surface.

mod client;
mod codec;
pub mod protocol;
mod transport;

pub use abyss_plugin_protocol::event::{
    AgentContext, AgentEvent, AgentEventSide, ContentCompleteness, Conversation,
    ConversationMessage, DeviceContext, ImageAttachment, ImageMediaType, LlmContext, LlmProvider,
    MessageRole, TokenUsage, ToolCall, ToolResult,
};
pub use client::{AgentEventStream, BrokerPlugin, BrokerPluginError};
pub use protocol::{
    BrokerClose, BrokerCloseCode, BrokerError, BrokerErrorCode, BrokerHello, PluginHello,
    PluginProtocolVersion,
};
