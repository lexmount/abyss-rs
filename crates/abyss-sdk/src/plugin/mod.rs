//! Public broker plugin runtime and protocol surface.

mod client;
mod codec;
pub mod protocol;
mod transport;

pub use abyss_plugin_protocol::event::{
    AgentContext, AgentEvent, AgentEventSide, ContentCategory, ContentCompleteness, Conversation,
    ConversationEntry, DeviceContext, EntryRole, EventPurpose, HttpHeader, HttpHeaderValue,
    ImageAttachment, ImageMediaType, LlmContext, LlmProvider, TokenUsage,
};
pub use abyss_plugin_protocol::inspection::*;
pub use client::{AgentEventStream, BrokerPlugin, BrokerPluginError, InspectingPlugin};
pub use protocol::{
    BrokerClose, BrokerCloseCode, BrokerError, BrokerErrorCode, BrokerHello, PluginHello,
    PluginProtocolVersion,
};
