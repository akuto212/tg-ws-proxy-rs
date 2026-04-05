pub mod dc;
pub mod error;
pub mod mtproto;
pub mod pool;
pub mod splitter;
pub mod stats;
pub mod tunnel;
pub mod ws;

pub use error::{ProxyError, Result};
pub use stats::ProxyStats;

use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub secret: String,       // 32 hex chars (16 bytes)
    pub pool_size: usize,
    pub buf_kb: usize,
    pub dc_redirects: HashMap<u8, String>,
}

/// Default WS-capable DC redirect IPs (used for WebSocket transport).
pub fn default_dc_redirects() -> HashMap<u8, String> {
    HashMap::from([
        (2, "149.154.167.220".into()),
        (4, "149.154.167.220".into()),
    ])
}

impl Default for ProxyConfig {
    fn default() -> Self {
        use rand::Rng;
        let secret_bytes: [u8; 16] = rand::rng().random();
        let secret = secret_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        Self {
            host: "127.0.0.1".into(),
            port: 1443,
            secret,
            pool_size: 4,
            buf_kb: 256,
            dc_redirects: default_dc_redirects(),
        }
    }
}

pub async fn start_proxy(config: ProxyConfig, cancel: CancellationToken) -> Result<Arc<ProxyStats>> {
    let stats = Arc::new(ProxyStats::default());
    start_proxy_with_stats(config, cancel, Arc::clone(&stats)).await?;
    Ok(stats)
}

/// Resolve the display host for tg:// links. If bound to 0.0.0.0, detect LAN IP.
pub fn get_link_host(host: &str) -> String {
    if host == "0.0.0.0" {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    return addr.ip().to_string();
                }
            }
        }
        "127.0.0.1".to_string()
    } else {
        host.to_string()
    }
}

/// Build the tg://proxy link for this proxy instance.
pub fn tg_proxy_link(host: &str, port: u16, secret: &str) -> String {
    let link_host = get_link_host(host);
    format!("tg://proxy?server={link_host}&port={port}&secret=dd{secret}")
}

pub async fn start_proxy_with_stats(
    config: ProxyConfig,
    cancel: CancellationToken,
    stats: Arc<ProxyStats>,
) -> Result<()> {
    // 1. Parse secret hex to [u8; 16]
    let secret_bytes: [u8; 16] = {
        let hex = &config.secret;
        let mut buf = [0u8; 16];
        for i in 0..16 {
            buf[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| ProxyError::Handshake("invalid secret hex".into()))?;
        }
        buf
    };

    // 2. Build WsFactory (always insecure TLS)
    let factory: ws::WsFactory = Arc::new(move |params| {
        Box::pin(async move {
            let transport = ws::tungstenite::TungsteniteTransport::connect(&params).await?;
            Ok(Box::new(transport) as Box<dyn ws::WsTransport>)
        })
    });

    // 3. Build pool
    let pool = pool::WsPool::new(
        Arc::clone(&factory),
        config.pool_size,
        std::time::Duration::from_secs(120),
        config.dc_redirects.clone(),
        Arc::clone(&stats),
    );

    // 4. Build tunnel context
    let tunnel_ctx = tunnel::TunnelCtx::new(
        Arc::clone(&pool),
        Arc::clone(&factory),
        Arc::clone(&stats),
        config.buf_kb * 1024,
        config.dc_redirects.clone(),
        secret_bytes,
    );

    // 5. Bind listener
    let bind_addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(ProxyError::Io)?;

    // 6. Log startup info
    let link = tg_proxy_link(&config.host, config.port, &config.secret);
    info!("============================================================");
    info!("  Telegram MTProto WS Bridge Proxy");
    info!("  Listening on   {}:{}", config.host, config.port);
    info!("  Secret:        {}", config.secret);
    info!("  Target DC IPs:");
    for dc in config.dc_redirects.keys() {
        info!("    DC{}: {}", dc, config.dc_redirects[dc]);
    }
    info!("============================================================");
    info!("  Connect link:");
    info!("    {}", link);
    info!("============================================================");

    // 7. Warm up pool (best-effort, no blacklisting on failure)
    {
        let pool_clone = Arc::clone(&pool);
        let warmup_dcs: Vec<(u8, bool)> = config
            .dc_redirects
            .keys()
            .flat_map(|&dc| vec![(dc, false), (dc, true)])
            .collect();
        tokio::spawn(async move {
            pool_clone.warmup(&warmup_dcs).await;
            debug!("Pool warmup complete");
        });
    }

    // 8. Accept loop
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _peer)) => {
                        let _ = stream.set_nodelay(true);
                        let ctx = Arc::clone(&tunnel_ctx);
                        tokio::spawn(async move {
                            tunnel::handle_client(ctx, stream).await;
                        });
                    }
                    Err(e) => {
                        warn!("Accept error: {e}");
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("Cancellation received, shutting down...");
                pool.shutdown().await;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                break;
            }
        }
    }

    Ok(())
}
