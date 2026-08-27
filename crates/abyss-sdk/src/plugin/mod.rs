//! Public broker plugin runtime and protocol surface.

mod client;
mod codec;
pub mod protocol;
mod transport;

pub use abyss_plugin_protocol::event::{
    AgentContext, AgentEvent, AgentEventSide, DeviceContext, ImageAttachment, ImageMediaType,
    LlmContext, LlmProvider, TokenUsage, ToolCall, ToolResult,
};
pub use client::{AbyssPlugin, AbyssPluginError, AgentEventStream};
pub use protocol::{
    BrokerClose, BrokerCloseCode, BrokerError, BrokerErrorCode, BrokerHello, PluginHello,
    PluginProtocolVersion,
};
