pub fn open_telegram_proxy(host: &str, port: u16, secret: &str) {
    let link = proxy_core::tg_proxy_link(host, port, secret);
    if let Err(e) = open::that(&link) {
        eprintln!("Failed to open Telegram: {e}");
    }
}

pub fn copy_to_clipboard(host: &str, port: u16, secret: &str) {
    let link = proxy_core::tg_proxy_link(host, port, secret);
    match arboard::Clipboard::new() {
        Ok(mut cb) => {
            let _ = cb.set_text(link);
        }
        Err(e) => eprintln!("Clipboard unavailable: {e}"),
    }
}
