#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod autosetup;
mod tray;

use clap::Parser;
use proxy_core::ProxyConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

#[derive(Parser)]
#[command(name = "tg-ws-proxy-rs", about = "Telegram MTProto WS Bridge Proxy")]
struct Cli {
    #[arg(short, long, default_value_t = 1443)]
    port: u16,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long)]
    secret: Option<String>,
    #[arg(long = "dc-ip")]
    dc_ip: Vec<String>,
    #[arg(long)]
    no_tray: bool,
    #[arg(long, default_value_t = 4)]
    pool_size: usize,
    #[arg(long, default_value_t = 64)]
    buf_kb: usize,
    #[arg(short, long)]
    verbose: bool,
    #[arg(long)]
    setup: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SavedConfig {
    pub secret: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub dc_ip: Option<Vec<String>>,
    #[serde(default)]
    pub pool_size: Option<usize>,
    #[serde(default)]
    pub buf_kb: Option<usize>,
    #[serde(default)]
    pub log_errors: Option<bool>,
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn config_path() -> PathBuf {
    exe_dir().join("config.json")
}

pub(crate) fn load_saved_config() -> Option<SavedConfig> {
    let path = config_path();
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

pub(crate) fn save_config(cfg: &SavedConfig) {
    let path = config_path();
    if let Ok(data) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(&path, data);
    }
}

fn validate_secret(s: &str) -> Result<String, String> {
    let s = s.trim().to_string();
    if s.len() != 32 {
        return Err("secret must be exactly 32 hex characters".into());
    }
    if s.chars().any(|c| !c.is_ascii_hexdigit()) {
        return Err("secret must be valid hex".into());
    }
    Ok(s)
}

fn parse_dc_ip_list(entries: &[String]) -> HashMap<u8, String> {
    let mut map = HashMap::new();
    for entry in entries {
        if let Some((dc_str, ip)) = entry.split_once(':') {
            if let Ok(dc) = dc_str.parse::<u8>() {
                map.insert(dc, ip.to_string());
            }
        }
    }
    map
}

fn main() {
    let cli = Cli::parse();
    let saved = load_saved_config();

    // Resolve secret: CLI flag > saved config > generate new
    let secret = if let Some(s) = &cli.secret {
        match validate_secret(s) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    } else if let Some(ref cfg) = saved {
        cfg.secret.clone()
    } else {
        use rand::Rng;
        let bytes: [u8; 16] = rand::rng().random();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    };

    let default_dc_ip: Vec<String> = proxy_core::default_dc_redirects()
        .iter()
        .map(|(dc, ip)| format!("{dc}:{ip}"))
        .collect();

    let saved_dc_ip: Vec<String> = if !cli.dc_ip.is_empty() {
        cli.dc_ip.clone()
    } else if let Some(ref cfg) = saved {
        cfg.dc_ip.clone().unwrap_or(default_dc_ip.clone())
    } else {
        default_dc_ip
    };

    let log_errors = saved.as_ref().and_then(|c| c.log_errors).unwrap_or(false);

    save_config(&SavedConfig {
        secret: secret.clone(),
        port: Some(cli.port),
        host: Some(cli.host.clone()),
        dc_ip: Some(saved_dc_ip.clone()),
        pool_size: Some(cli.pool_size),
        buf_kb: Some(cli.buf_kb),
        log_errors: Some(log_errors),
    });

    if cli.setup {
        autosetup::open_telegram_proxy(&cli.host, cli.port, &secret);
        return;
    }

    #[cfg(all(target_os = "windows", not(debug_assertions)))]
    if cli.no_tray {
        unsafe {
            windows_sys::Win32::System::Console::AllocConsole();
        }
    }

    let dc_redirects = parse_dc_ip_list(&saved_dc_ip);

    let config = ProxyConfig {
        host: cli.host.clone(),
        port: cli.port,
        secret: secret.clone(),
        pool_size: cli.pool_size,
        buf_kb: cli.buf_kb,
        dc_redirects,
    };

    let cancel = CancellationToken::new();

    if cli.no_tray {
        let level = if cli.verbose { "debug" } else { "info" };
        tracing_subscriber::fmt()
            .with_env_filter(level)
            .with_timer(tracing_subscriber::fmt::time::time())
            .with_target(false)
            .init();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cancel_sig = cancel.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                tracing::info!("Ctrl+C received, shutting down...");
                cancel_sig.cancel();
            });
            match proxy_core::start_proxy(config, cancel).await {
                Ok(_) => tracing::info!("Proxy stopped."),
                Err(e) => tracing::error!("Proxy error: {e}"),
            }
        });
    } else {
        let log_path = exe_dir().join("proxy-errors.log");

        let file_appender = tracing_appender::rolling::never(
            log_path.parent().unwrap_or(std::path::Path::new(".")),
            log_path.file_name().unwrap_or(std::ffi::OsStr::new("proxy-errors.log")),
        );
        let initial_filter = if log_errors { "proxy_core=warn" } else { "off" };
        let (file_filter, reload_handle) =
            tracing_subscriber::reload::Layer::new(EnvFilter::new(initial_filter));
        let file_layer = fmt::layer()
            .with_writer(file_appender)
            .with_timer(tracing_subscriber::fmt::time::time())
            .with_target(true)
            .with_ansi(false)
            .with_filter(file_filter);

        tracing_subscriber::registry().with(file_layer).init();

        let stats = Arc::new(proxy_core::ProxyStats::default());
        let (stats_tx, stats_rx) = tokio::sync::watch::channel("Connections: 0".to_string());
        let cancel_proxy = cancel.clone();
        let stats_proxy = Arc::clone(&stats);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let cancel_sig = cancel_proxy.clone();
                tokio::spawn(async move {
                    tokio::signal::ctrl_c().await.ok();
                    cancel_sig.cancel();
                });

                let stats_ref = Arc::clone(&stats_proxy);
                let cancel_stats = cancel_proxy.clone();
                let stats_updater = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        if cancel_stats.is_cancelled() {
                            break;
                        }
                        let total = stats_ref.get(&stats_ref.connections_total);
                        let active = stats_ref.get(&stats_ref.connections_active);
                        let ws = stats_ref.get(&stats_ref.connections_ws);
                        let text = format!("Total: {total}  Active: {active}  WS: {ws}");
                        let _ = stats_tx.send(text);
                    }
                });

                match proxy_core::start_proxy_with_stats(config, cancel_proxy, stats_proxy).await {
                    Ok(_) => {}
                    Err(e) => tracing::error!("Proxy error: {e}"),
                }

                stats_updater.abort();
            });
        });

        tray::run_tray(
            tray::TrayState {
                host: cli.host,
                port: cli.port,
                secret,
                log_errors,
            },
            stats_rx,
            cancel,
            reload_handle,
        );
    }
}
