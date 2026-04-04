use muda::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tray_icon::TrayIconBuilder;
use tracing_subscriber::{reload, EnvFilter};

static ICON_BYTES: &[u8] = include_bytes!("../../../assets/icon.png");

const APP_NAME: &str = "tg-ws-proxy-rs";

pub struct TrayState {
    pub host: String,
    pub port: u16,
    pub secret: String,
    pub log_errors: bool,
}

// ── Autostart (Windows registry) ──────────────────────────────────────

#[cfg(target_os = "windows")]
mod autostart {
    use super::APP_NAME;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Registry::*;

    const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn autostart_command() -> String {
        let exe = std::env::current_exe().unwrap_or_default();
        format!("\"{}\"", exe.display())
    }

    pub fn is_enabled() -> bool {
        unsafe {
            let key_wide = wide(RUN_KEY);
            let name_wide = wide(APP_NAME);
            let mut hkey: HKEY = std::ptr::null_mut() as _;
            if RegOpenKeyExW(HKEY_CURRENT_USER, key_wide.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
                return false;
            }

            let mut buf = [0u16; 1024];
            let mut buf_size = (buf.len() * 2) as u32;
            let mut reg_type: u32 = 0;
            let result = RegQueryValueExW(
                hkey,
                name_wide.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                buf.as_mut_ptr() as *mut u8,
                &mut buf_size,
            );
            RegCloseKey(hkey);

            if result != 0 {
                return false;
            }

            let len = (buf_size as usize) / 2;
            let val = OsString::from_wide(&buf[..len])
                .to_string_lossy()
                .trim_end_matches('\0')
                .trim()
                .to_string();
            val == autostart_command().trim()
        }
    }

    pub fn set_enabled(enabled: bool) {
        unsafe {
            let key_wide = wide(RUN_KEY);
            let name_wide = wide(APP_NAME);
            let mut hkey: HKEY = std::ptr::null_mut() as _;

            if RegOpenKeyExW(HKEY_CURRENT_USER, key_wide.as_ptr(), 0, KEY_WRITE, &mut hkey) != 0 {
                let mut hkey2: HKEY = std::ptr::null_mut() as _;
                if RegCreateKeyW(HKEY_CURRENT_USER, key_wide.as_ptr(), &mut hkey2) != 0 {
                    return;
                }
                hkey = hkey2;
            }

            if enabled {
                let cmd_wide = wide(&autostart_command());
                RegSetValueExW(
                    hkey,
                    name_wide.as_ptr(),
                    0,
                    REG_SZ,
                    cmd_wide.as_ptr() as *const u8,
                    (cmd_wide.len() * 2) as u32,
                );
            } else {
                RegDeleteValueW(hkey, name_wide.as_ptr());
            }
            RegCloseKey(hkey);
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod autostart {
    pub fn is_enabled() -> bool {
        false
    }
    pub fn set_enabled(_enabled: bool) {}
}

pub fn run_tray(
    state: TrayState,
    mut stats_rx: watch::Receiver<String>,
    cancel: CancellationToken,
    reload_handle: reload::Handle<EnvFilter, impl tracing::Subscriber + Send + Sync + 'static>,
) {
    #[cfg(target_os = "macos")]
    init_macos_app();

    let decoder = png::Decoder::new(std::io::Cursor::new(ICON_BYTES));
    let mut reader = decoder.read_info().expect("invalid icon PNG");
    let mut icon_buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut icon_buf).expect("icon decode failed");
    let icon_data = icon_buf[..info.buffer_size()].to_vec();
    let icon = tray_icon::Icon::from_rgba(icon_data, info.width, info.height)
        .expect("icon creation failed");

    let status_item = MenuItem::new("Proxy running", false, None);
    let stats_item = MenuItem::new("Connections: 0", false, None);
    let autostart_toggle = CheckMenuItem::new(
        "Run at startup",
        true,
        autostart::is_enabled(),
        None,
    );
    let log_toggle = CheckMenuItem::new("Log errors", true, state.log_errors, None);
    let open_tg = MenuItem::new("Open in Telegram", true, None);
    let copy_link = MenuItem::new("Copy tg:// link", true, None);
    let exit_item = MenuItem::new("Exit", true, None);

    let menu = Menu::new();
    menu.append(&status_item).unwrap();
    menu.append(&stats_item).unwrap();
    menu.append(&PredefinedMenuItem::separator()).unwrap();
    menu.append(&autostart_toggle).unwrap();
    menu.append(&log_toggle).unwrap();
    menu.append(&PredefinedMenuItem::separator()).unwrap();
    menu.append(&open_tg).unwrap();
    menu.append(&copy_link).unwrap();
    menu.append(&PredefinedMenuItem::separator()).unwrap();
    menu.append(&exit_item).unwrap();

    let _tray = TrayIconBuilder::new()
        .with_tooltip(APP_NAME)
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .build()
        .expect("failed to create tray icon");

    let open_tg_id = open_tg.id().clone();
    let copy_link_id = copy_link.id().clone();
    let autostart_toggle_id = autostart_toggle.id().clone();
    let log_toggle_id = log_toggle.id().clone();
    let exit_id = exit_item.id().clone();

    let menu_rx = MenuEvent::receiver();

    loop {
        #[cfg(target_os = "windows")]
        pump_win32_messages();

        #[cfg(target_os = "macos")]
        pump_macos_events();

        if let Ok(event) = menu_rx.try_recv() {
            if event.id == open_tg_id {
                crate::autosetup::open_telegram_proxy(&state.host, state.port, &state.secret);
            } else if event.id == copy_link_id {
                crate::autosetup::copy_to_clipboard(&state.host, state.port, &state.secret);
            } else if event.id == autostart_toggle_id {
                autostart::set_enabled(autostart_toggle.is_checked());
            } else if event.id == log_toggle_id {
                let enabled = log_toggle.is_checked();
                if enabled {
                    let _ = reload_handle
                        .modify(|f| *f = EnvFilter::new("proxy_core=warn"));
                } else {
                    let _ = reload_handle.modify(|f| *f = EnvFilter::new("off"));
                }
                if let Some(mut cfg) = crate::load_saved_config() {
                    cfg.log_errors = Some(enabled);
                    crate::save_config(&cfg);
                }

            } else if event.id == exit_id {
                cancel.cancel();
                break;
            }
        }

        if stats_rx.has_changed().unwrap_or(false) {
            let text = stats_rx.borrow_and_update().clone();
            stats_item.set_text(&text);
        }

        std::thread::sleep(std::time::Duration::from_millis(100));

        if cancel.is_cancelled() {
            break;
        }
    }
}

// ── macOS event loop ─────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::c_void;

    #[link(name = "AppKit", kind = "framework")]
    extern "C" {}

    #[link(name = "Foundation", kind = "framework")]
    extern "C" {
        pub(super) static NSDefaultRunLoopMode: *mut c_void;
    }

    extern "C" {
        pub(super) fn objc_getClass(name: *const u8) -> *mut c_void;
        pub(super) fn sel_registerName(name: *const u8) -> *mut c_void;
        pub(super) fn objc_msgSend();
    }

    pub(super) type Send0 =
        unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
    pub(super) type SendI64 =
        unsafe extern "C" fn(*mut c_void, *mut c_void, i64) -> *mut c_void;
    pub(super) type SendNextEvent =
        unsafe extern "C" fn(*mut c_void, *mut c_void, u64, *mut c_void, *mut c_void, i8) -> *mut c_void;
    pub(super) type SendVoidPtr =
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
}

#[cfg(target_os = "macos")]
fn init_macos_app() {
    use macos::*;

    unsafe {
        let send0: Send0 = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let send_i64: SendI64 = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());

        let cls = objc_getClass(b"NSApplication\0".as_ptr());
        let sel = sel_registerName(b"sharedApplication\0".as_ptr());
        let app = send0(cls, sel);

        // NSApplicationActivationPolicyAccessory = 1 (no dock icon)
        let sel = sel_registerName(b"setActivationPolicy:\0".as_ptr());
        send_i64(app, sel, 1);

        // finishLaunching — required for proper event delivery
        let sel = sel_registerName(b"finishLaunching\0".as_ptr());
        send0(app, sel);
    }
}

#[cfg(target_os = "macos")]
fn pump_macos_events() {
    use macos::*;

    unsafe {
        let send0: Send0 = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let send_next: SendNextEvent = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        let send_evt: SendVoidPtr = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());

        let app = send0(
            objc_getClass(b"NSApplication\0".as_ptr()),
            sel_registerName(b"sharedApplication\0".as_ptr()),
        );

        let distant_past = send0(
            objc_getClass(b"NSDate\0".as_ptr()),
            sel_registerName(b"distantPast\0".as_ptr()),
        );

        let next_sel = sel_registerName(
            b"nextEventMatchingMask:untilDate:inMode:dequeue:\0".as_ptr(),
        );
        let send_sel = sel_registerName(b"sendEvent:\0".as_ptr());

        // Drain all pending events (NSEventMaskAny = u64::MAX)
        loop {
            let event = send_next(
                app,
                next_sel,
                u64::MAX,
                distant_past,
                NSDefaultRunLoopMode,
                1, // YES — dequeue
            );
            if event.is_null() {
                break;
            }
            send_evt(app, send_sel, event);
        }
    }
}

#[cfg(target_os = "windows")]
fn pump_win32_messages() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
    };
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
