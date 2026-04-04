use crate::dc::{dc_default_ips, dc_override};
use crate::mtproto::{self, HANDSHAKE_LEN};
use crate::pool::{resolve_dc_ip, WsPool};
use crate::splitter::MsgSplitter;
use crate::stats::ProxyStats;
use crate::ws::{ws_domains, WsConnectParams, WsFactory, WsTransport};
use cipher::StreamCipher;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
type DcKey = (u8, bool);

const BLACKLIST_DURATION: Duration = Duration::from_secs(300);
const DC_FAIL_COOLDOWN: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

// ── FailTracker ───────────────────────────────────────────────────────

pub(crate) struct FailTracker {
    blacklist: HashMap<DcKey, Instant>,
    cooldown: HashMap<DcKey, Instant>,
}

impl FailTracker {
    fn new() -> Self {
        Self {
            blacklist: HashMap::new(),
            cooldown: HashMap::new(),
        }
    }

    pub fn is_blacklisted(&self, key: &DcKey) -> bool {
        self.blacklist
            .get(key)
            .map(|t| t.elapsed() < BLACKLIST_DURATION)
            .unwrap_or(false)
    }

    pub fn is_in_cooldown(&self, key: &DcKey) -> bool {
        self.cooldown
            .get(key)
            .map(|t| t.elapsed() < DC_FAIL_COOLDOWN)
            .unwrap_or(false)
    }

    pub fn ws_timeout(&self, key: &DcKey) -> Duration {
        if self.is_in_cooldown(key) {
            Duration::from_secs(5)
        } else {
            WS_CONNECT_TIMEOUT
        }
    }

    pub fn record_failure(&mut self, key: DcKey, blacklist: bool) {
        if blacklist {
            self.blacklist.insert(key, Instant::now());
        }
        self.cooldown.insert(key, Instant::now());
    }

    pub fn clear_cooldown(&mut self, key: &DcKey) {
        self.cooldown.remove(key);
    }
}

// ── TunnelCtx ─────────────────────────────────────────────────────────

pub struct TunnelCtx {
    pub pool: Arc<WsPool>,
    pub factory: WsFactory,
    pub(crate) fail_tracker: Mutex<FailTracker>,
    pub stats: Arc<ProxyStats>,
    pub buf_size: usize,
    pub dc_redirects: HashMap<u8, String>,
    pub secret: [u8; 16],
}

impl TunnelCtx {
    pub fn new(
        pool: Arc<WsPool>,
        factory: WsFactory,
        stats: Arc<ProxyStats>,
        buf_size: usize,
        dc_redirects: HashMap<u8, String>,
        secret: [u8; 16],
    ) -> Arc<Self> {
        Arc::new(Self {
            pool,
            factory,
            fail_tracker: Mutex::new(FailTracker::new()),
            stats,
            buf_size,
            dc_redirects,
            secret,
        })
    }
}

// ── handle_client ─────────────────────────────────────────────────────

pub async fn handle_client(ctx: Arc<TunnelCtx>, mut client: TcpStream) {
    ctx.stats.inc(&ctx.stats.connections_total);
    ctx.stats.inc(&ctx.stats.connections_active);

    let result = handle_client_inner(&ctx, &mut client).await;
    if let Err(e) = result {
        debug!("Client handler finished with error: {e}");
    }

    ctx.stats.dec(&ctx.stats.connections_active);
}

async fn handle_client_inner(
    ctx: &Arc<TunnelCtx>,
    client: &mut TcpStream,
) -> crate::Result<()> {
    // 1. Read 64-byte handshake with timeout
    let mut handshake = [0u8; HANDSHAKE_LEN];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut handshake)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            debug!("Failed to read handshake: {e}");
            return Err(e.into());
        }
        Err(_) => {
            debug!("Handshake read timed out");
            return Err(crate::ProxyError::Timeout);
        }
    }

    // 2. Validate handshake
    let hs = match mtproto::try_handshake(&handshake, &ctx.secret) {
        Some(hs) => hs,
        None => {
            ctx.stats.inc(&ctx.stats.connections_bad);
            debug!("Bad handshake, draining client");
            // Drain remaining data to avoid RST
            let mut drain_buf = [0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match client.read(&mut drain_buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => continue,
                    }
                }
            })
            .await;
            return Err(crate::ProxyError::Handshake("invalid handshake".into()));
        }
    };

    let dc = hs.dc;
    let is_media = hs.is_media;
    let proto_tag = hs.proto_tag;
    let proto_int = hs.proto_int;
    let client_dec_prekey_iv = hs.client_dec_prekey_iv;

    let dc_idx: i16 = if is_media { -(dc as i16) } else { dc as i16 };

    info!("MTProto handshake: DC{dc} media={is_media} proto=0x{proto_int:08X}");

    // 3. Generate relay init and build ciphers
    let relay_init = mtproto::generate_relay_init(&proto_tag, dc_idx);
    let (clt_decryptor, clt_encryptor, tg_encryptor, tg_decryptor) =
        mtproto::build_ciphers(&client_dec_prekey_iv, &ctx.secret, &relay_init);

    let dk: DcKey = (dc, is_media);

    // 4. Decide WS vs TCP fallback
    let dc_ws = dc_override(dc);
    let should_try_ws = {
        let ft = ctx.fail_tracker.lock().await;
        ctx.dc_redirects.contains_key(&dc_ws) && !ft.is_blacklisted(&dk)
    };

    if should_try_ws {
        // Try pool first
        let pool_ws = ctx.pool.get(dc, is_media).await;
        let ws = if let Some(ws) = pool_ws {
            debug!("DC{dc} media={is_media}: pool hit");
            Some(ws)
        } else {
            // Try fresh WS connection
            let timeout = {
                let ft = ctx.fail_tracker.lock().await;
                ft.ws_timeout(&dk)
            };
            match try_ws_connect(ctx, &relay_init, dc, is_media, timeout).await {
                Ok(ws) => {
                    let mut ft = ctx.fail_tracker.lock().await;
                    ft.clear_cooldown(&dk);
                    Some(ws)
                }
                Err(e) => {
                    warn!("WS connect failed for DC{dc} media={is_media}: {e}");
                    let mut ft = ctx.fail_tracker.lock().await;
                    ft.record_failure(dk, false);
                    ctx.stats.inc(&ctx.stats.ws_errors);
                    None
                }
            }
        };

        if let Some(mut ws) = ws {
            // Send relay_init over WS
            if let Err(e) = ws.send(&relay_init).await {
                warn!("Failed to send relay_init over WS: {e}");
                let mut ft = ctx.fail_tracker.lock().await;
                ft.record_failure(dk, false);
                ctx.stats.inc(&ctx.stats.ws_errors);
            } else {
                ctx.stats.inc(&ctx.stats.connections_ws);

                // Build splitter from relay_init's key/iv
                let splitter_key = &relay_init[8..40];
                let splitter_iv = &relay_init[40..56];
                let splitter = MsgSplitter::new(splitter_key, splitter_iv, proto_int);

                let result = bridge_ws_reencrypt(
                    ctx, client, ws, splitter,
                    clt_decryptor, clt_encryptor, tg_encryptor, tg_decryptor,
                )
                .await;

                ctx.stats.dec(&ctx.stats.connections_ws);

                if let Err(e) = result {
                    debug!("WS bridge ended: {e}");
                }
                return Ok(());
            }
        }
    }

    // TCP fallback
    debug!("DC{dc} media={is_media}: falling back to TCP");
    tcp_fallback_reencrypt(
        ctx, client, dc, &relay_init,
        clt_decryptor, clt_encryptor, tg_encryptor, tg_decryptor,
    )
    .await
}

// ── try_ws_connect ────────────────────────────────────────────────────

async fn try_ws_connect(
    ctx: &Arc<TunnelCtx>,
    _relay_init: &[u8; HANDSHAKE_LEN],
    dc: u8,
    is_media: bool,
    timeout: Duration,
) -> crate::Result<Box<dyn WsTransport>> {
    let target_ip = resolve_dc_ip(dc, is_media, &ctx.dc_redirects);
    let domains = ws_domains(dc, is_media);

    for domain in &domains {
        let params = WsConnectParams {
            target_ip: target_ip.clone(),
            domain: domain.clone(),
            path: "/apiws".to_string(),
        };
        match tokio::time::timeout(timeout, (ctx.factory)(params)).await {
            Ok(Ok(ws)) => {
                debug!("WS connected to DC{dc} media={is_media} via {domain}");
                return Ok(ws);
            }
            Ok(Err(e)) => {
                debug!("WS connect failed via {domain}: {e}");
            }
            Err(_) => {
                debug!("WS connect timed out via {domain}");
            }
        }
    }

    Err(crate::ProxyError::WebSocket(format!(
        "all WS domains exhausted for DC{dc} media={is_media}"
    )))
}

// ── bridge_ws_reencrypt ───────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn bridge_ws_reencrypt(
    ctx: &Arc<TunnelCtx>,
    client: &mut TcpStream,
    ws: Box<dyn WsTransport>,
    mut splitter: MsgSplitter,
    mut clt_decryptor: Aes256Ctr,
    mut clt_encryptor: Aes256Ctr,
    mut tg_encryptor: Aes256Ctr,
    mut tg_decryptor: Aes256Ctr,
) -> crate::Result<()> {
    let (client_read, client_write) = client.split();
    let (mut ws_tx, mut ws_rx) = ws.split();

    let buf_size = ctx.buf_size;
    let stats = Arc::clone(&ctx.stats);
    let stats2 = Arc::clone(&ctx.stats);

    // Upload: client → decrypt → re-encrypt → WS
    let upload = async move {
        let mut reader = tokio::io::BufReader::new(client_read);
        let mut buf = vec![0u8; buf_size];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), crate::ProxyError>(());
            }

            let data = &mut buf[..n];
            // Decrypt from client
            clt_decryptor.apply_keystream(data);
            // Re-encrypt for Telegram
            tg_encryptor.apply_keystream(data);

            stats.add(&stats.bytes_up, n as u64);

            // Split into message boundaries
            let boundaries = splitter.split(data);

            if boundaries.is_empty() {
                // No complete message boundary — send as single chunk
                ws_tx.send(data).await?;
            } else {
                // Send as batch split on boundaries
                let mut parts: Vec<&[u8]> = Vec::new();
                let mut prev = 0;
                for &boundary in &boundaries {
                    if boundary > prev {
                        parts.push(&data[prev..boundary]);
                    }
                    prev = boundary;
                }
                // Remaining data after last boundary
                if prev < data.len() {
                    parts.push(&data[prev..]);
                }
                ws_tx.send_batch(&parts).await?;
            }
        }
    };

    // Download: WS → decrypt → re-encrypt → client
    let download = async move {
        let mut writer = client_write;

        loop {
            let msg = ws_rx.recv().await?;
            match msg {
                None => return Ok::<(), crate::ProxyError>(()),
                Some(mut data) => {
                    // Decrypt from Telegram
                    tg_decryptor.apply_keystream(&mut data);
                    // Re-encrypt for client
                    clt_encryptor.apply_keystream(&mut data);

                    stats2.add(&stats2.bytes_down, data.len() as u64);
                    writer.write_all(&data).await?;
                }
            }
        }
    };

    tokio::select! {
        r = upload => r,
        r = download => r,
    }
}

// ── tcp_fallback_reencrypt ────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn tcp_fallback_reencrypt(
    ctx: &Arc<TunnelCtx>,
    client: &mut TcpStream,
    dc: u8,
    relay_init: &[u8; HANDSHAKE_LEN],
    mut clt_decryptor: Aes256Ctr,
    mut clt_encryptor: Aes256Ctr,
    mut tg_encryptor: Aes256Ctr,
    mut tg_decryptor: Aes256Ctr,
) -> crate::Result<()> {
    // Resolve target IP
    let default_ips = dc_default_ips();
    let ip = ctx
        .dc_redirects
        .get(&dc)
        .map(|s| s.as_str())
        .or_else(|| default_ips.get(&dc).copied())
        .ok_or_else(|| {
            crate::ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no IP for DC{dc}"),
            ))
        })?;

    let addr = format!("{ip}:443");
    debug!("TCP fallback connecting to {addr} for DC{dc}");

    let mut upstream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| crate::ProxyError::Timeout)?
    .map_err(crate::ProxyError::Io)?;

    // Send relay_init to Telegram
    upstream.write_all(relay_init).await?;

    ctx.stats.inc(&ctx.stats.connections_tcp_fallback);

    let buf_size = ctx.buf_size;
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();

    let stats = Arc::clone(&ctx.stats);
    let stats2 = Arc::clone(&ctx.stats);

    // Upload: client → decrypt → re-encrypt → Telegram TCP
    let upload = async move {
        let mut reader = tokio::io::BufReader::new(client_read);
        let mut writer = upstream_write;
        let mut buf = vec![0u8; buf_size];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), crate::ProxyError>(());
            }

            let data = &mut buf[..n];
            clt_decryptor.apply_keystream(data);
            tg_encryptor.apply_keystream(data);

            stats.add(&stats.bytes_up, n as u64);
            writer.write_all(data).await?;
        }
    };

    // Download: Telegram TCP → decrypt → re-encrypt → client
    let download = async move {
        let mut reader = tokio::io::BufReader::new(upstream_read);
        let mut writer = client_write;
        let mut buf = vec![0u8; buf_size];

        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok::<(), crate::ProxyError>(());
            }

            let data = &mut buf[..n];
            tg_decryptor.apply_keystream(data);
            clt_encryptor.apply_keystream(data);

            stats2.add(&stats2.bytes_down, n as u64);
            writer.write_all(data).await?;
        }
    };

    let result = tokio::select! {
        r = upload => r,
        r = download => r,
    };

    ctx.stats.dec(&ctx.stats.connections_tcp_fallback);
    result
}
