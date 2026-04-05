use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    #[error("Handshake error: {0}")]
    Handshake(String),
    #[error("WS redirect (302)")]
    WsRedirect,
    #[error("Timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, ProxyError>;
