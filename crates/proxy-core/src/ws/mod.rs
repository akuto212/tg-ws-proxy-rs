pub mod tungstenite;

use crate::error::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Parameters for creating a WS connection.
pub struct WsConnectParams {
    pub target_ip: Option<String>,  // IP to connect to (bypasses DNS). None = resolve domain via DNS.
    pub domain: String,             // Domain for TLS SNI and Host header
    pub path: String,               // e.g. "/apiws"
}

/// Abstract WebSocket transport. Swap implementations without changing tunnel/pool.
#[allow(clippy::type_complexity)]
pub trait WsTransport: Send + 'static {
    fn send(&mut self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
    fn send_batch(&mut self, parts: &[&[u8]]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>>;
    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
    fn is_closed(&self) -> bool;
    /// Split into independent send/recv halves for concurrent bidirectional I/O.
    fn split(self: Box<Self>) -> (Box<dyn WsSender>, Box<dyn WsReceiver>);
}

/// Send half of a split WebSocket transport.
pub trait WsSender: Send + 'static {
    fn send(&mut self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
    fn send_batch(&mut self, parts: &[&[u8]]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// Receive half of a split WebSocket transport.
#[allow(clippy::type_complexity)]
pub trait WsReceiver: Send + 'static {
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>>;
}

/// Factory for creating WsTransport instances.
pub type WsFactory = Arc<
    dyn Fn(WsConnectParams) -> Pin<Box<dyn Future<Output = Result<Box<dyn WsTransport>>> + Send>>
        + Send + Sync,
>;

/// Build WS domain list for a DC. Media prefers `-1` subdomain first.
pub fn ws_domains(dc: u8, is_media: bool) -> Vec<String> {
    let dc_ws = crate::dc::dc_override(dc);
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", dc_ws),
            format!("kws{}.web.telegram.org", dc_ws),
        ]
    } else {
        vec![
            format!("kws{}.web.telegram.org", dc_ws),
            format!("kws{}-1.web.telegram.org", dc_ws),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_domains_non_media_dc2() {
        let domains = ws_domains(2, false);
        assert_eq!(
            domains,
            vec![
                "kws2.web.telegram.org".to_string(),
                "kws2-1.web.telegram.org".to_string(),
            ]
        );
    }

    #[test]
    fn test_ws_domains_media_dc2() {
        let domains = ws_domains(2, true);
        assert_eq!(
            domains,
            vec![
                "kws2-1.web.telegram.org".to_string(),
                "kws2.web.telegram.org".to_string(),
            ]
        );
    }

    #[test]
    fn test_ws_domains_dc203_override() {
        // DC203 maps to dc_ws=2 via dc_override
        let domains = ws_domains(203, false);
        assert_eq!(
            domains,
            vec![
                "kws2.web.telegram.org".to_string(),
                "kws2-1.web.telegram.org".to_string(),
            ]
        );
    }

    #[test]
    fn test_ws_domains_dc203_media_override() {
        let domains = ws_domains(203, true);
        assert_eq!(
            domains,
            vec![
                "kws2-1.web.telegram.org".to_string(),
                "kws2.web.telegram.org".to_string(),
            ]
        );
    }
}
