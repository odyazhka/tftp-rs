mod app;
mod history;
#[allow(dead_code)] // get_file и run_server пока не используются GUI
mod tftp;
mod theme;

/// winit (на нём работает eframe) не умеет drag&drop под Wayland — событие просто не приходит.
/// Поэтому на Linux принудительно берём X11-бэкенд (в Wayland-сессии это XWayland).
/// Если нужно отключить: запустите с WINIT_UNIX_BACKEND=wayland.
#[cfg(target_os = "linux")]
fn prefer_x11_for_drag_and_drop() {
    if std::env::var_os("DISPLAY").is_none() || std::env::var_os("WINIT_UNIX_BACKEND").is_some() {
        return;
    }
    #[allow(unused_unsafe)] // в edition 2024 set_var помечена unsafe, в 2021 — нет
    unsafe {
        std::env::set_var("WINIT_UNIX_BACKEND", "x11");
    }
}

fn main() -> eframe::Result<()> {
    #[cfg(target_os = "linux")]
    prefer_x11_for_drag_and_drop();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("tftp-rs")
            .with_app_id("tftp-rs") // должен совпадать с StartupWMClass в tftp-rs.desktop
            .with_inner_size([640.0, 560.0])
            .with_min_inner_size([480.0, 420.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "tftp-rs",
        options,
        Box::new(|cc| {
            theme::setup(&cc.egui_ctx);
            Ok(Box::new(app::TftpApp::default()))
        }),
    )
}
