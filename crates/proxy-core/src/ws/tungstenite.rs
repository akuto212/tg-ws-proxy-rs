use crate::error::{ProxyError, Result};
use crate::ws::{WsReceiver, WsSender, WsTransport};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

type TlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
type WsStream = tokio_tungstenite::WebSocketStream<TlsStream>;

pub struct TungsteniteTransport {
    ws: WsStream,
    closed: bool,
}

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build a rustls ClientConfig with certificate verification disabled.
fn make_insecure_config() -> ClientConfig {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .expect("valid protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}


impl TungsteniteTransport {
    pub async fn connect(params: &crate::ws::WsConnectParams) -> Result<Self> {
        let tls_config = make_insecure_config();
        let connector = TlsConnector::from(Arc::new(tls_config));

        // Connect TCP: use target IP if provided (bypass DNS), otherwise resolve domain.
        let connect_addr = match &params.target_ip {
            Some(ip) => format!("{ip}:443"),
            None => format!("{}:443", params.domain),
        };
        let tcp = tokio::net::TcpStream::connect(&connect_addr)
            .await
            .map_err(ProxyError::Io)?;
        let _ = tcp.set_nodelay(true);

        // TLS with domain as SNI.
        let server_name = ServerName::try_from(params.domain.clone())
            .map_err(|e| ProxyError::WebSocket(format!("Invalid server name: {e}")))?;
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(ProxyError::Io)?;

        // WS upgrade — let tungstenite build proper WS request from URL, then add custom headers.
        let url = format!("wss://{}{}", params.domain, params.path);
        let mut request = url
            .into_client_request()
            .map_err(|e| ProxyError::WebSocket(e.to_string()))?;
        {
            let headers = request.headers_mut();
            headers.insert(
                "Sec-WebSocket-Protocol",
                "binary".parse().unwrap(),
            );
            headers.insert(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                    .parse()
                    .unwrap(),
            );
            headers.insert("Origin", "https://web.telegram.org".parse().unwrap());
        }

        let (ws, _response) = tokio_tungstenite::client_async(request, tls_stream)
            .await
            .map_err(|e| ProxyError::WebSocket(e.to_string()))?;

        Ok(Self { ws, closed: false })
    }
}

impl WsTransport for TungsteniteTransport {
    fn send(&mut self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let msg = Message::Binary(data.to_vec());
        Box::pin(async move {
            self.ws
                .send(msg)
                .await
                .map_err(|e| ProxyError::WebSocket(e.to_string()))
        })
    }

    fn send_batch(
        &mut self,
        parts: &[&[u8]],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let messages: Vec<Message> = parts
            .iter()
            .map(|p| Message::Binary(p.to_vec()))
            .collect();
        Box::pin(async move {
            for msg in messages {
                self.ws
                    .feed(msg)
                    .await
                    .map_err(|e| ProxyError::WebSocket(e.to_string()))?;
            }
            self.ws
                .flush()
                .await
                .map_err(|e| ProxyError::WebSocket(e.to_string()))
        })
    }

    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                match self.ws.next().await {
                    Some(Ok(Message::Binary(data))) => {
                        return Ok(Some(data.to_vec()));
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        // Auto-respond with Pong.
                        self.ws
                            .send(Message::Pong(payload))
                            .await
                            .map_err(|e| ProxyError::WebSocket(e.to_string()))?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => {
                        self.closed = true;
                        return Ok(None);
                    }
                    Some(Ok(Message::Text(_))) => {}
                    Some(Ok(Message::Frame(_))) => {}
                    Some(Err(e)) => {
                        self.closed = true;
                        return Err(ProxyError::WebSocket(e.to_string()));
                    }
                }
            }
        })
    }

    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            self.closed = true;
            self.ws
                .close(None)
                .await
                .map_err(|e| ProxyError::WebSocket(e.to_string()))
        })
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn split(self: Box<Self>) -> (Box<dyn WsSender>, Box<dyn WsReceiver>) {
        let (sink, stream) = self.ws.split();
        (
            Box::new(TungsteniteSender { sink }),
            Box::new(TungsteniteReceiver { stream }),
        )
    }
}

// ── Split halves for concurrent bidirectional I/O ───────────────────────────

pub struct TungsteniteSender {
    sink: SplitSink<WsStream, Message>,
}

pub struct TungsteniteReceiver {
    stream: SplitStream<WsStream>,
}

impl WsSender for TungsteniteSender {
    fn send(&mut self, data: &[u8]) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let msg = Message::Binary(data.to_vec());
        Box::pin(async move {
            self.sink
                .send(msg)
                .await
                .map_err(|e| ProxyError::WebSocket(e.to_string()))
        })
    }

    fn send_batch(
        &mut self,
        parts: &[&[u8]],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let messages: Vec<Message> = parts
            .iter()
            .map(|p| Message::Binary(p.to_vec()))
            .collect();
        Box::pin(async move {
            for msg in messages {
                self.sink
                    .feed(msg)
                    .await
                    .map_err(|e| ProxyError::WebSocket(e.to_string()))?;
            }
            self.sink
                .flush()
                .await
                .map_err(|e| ProxyError::WebSocket(e.to_string()))
        })
    }
}

impl WsReceiver for TungsteniteReceiver {
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                match self.stream.next().await {
                    Some(Ok(Message::Binary(data))) => {
                        return Ok(Some(data.to_vec()));
                    }
                    Some(Ok(Message::Ping(_))) => {
                        // Pong is auto-queued by tungstenite internally via BiLock.
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => {
                        return Ok(None);
                    }
                    Some(Ok(Message::Text(_))) => {}
                    Some(Ok(Message::Frame(_))) => {}
                    Some(Err(e)) => {
                        return Err(ProxyError::WebSocket(e.to_string()));
                    }
                }
            }
        })
    }
}

// ── NoVerifier: accept any certificate (equivalent to ssl.CERT_NONE) ─────────

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crypto_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
