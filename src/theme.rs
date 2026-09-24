//! Фирменный стиль (как в AverStor): чёрный фон, белый текст, шрифт Terminus,
//! кнопки-контуры с заливкой при наведении и сплошные кнопки для главных действий.
//!
//! Шрифты лежат в `assets/`:
//!   assets/Terminus__TTF__500.ttf
//!   assets/Terminus__TTF__Bold_700.ttf

use eframe::egui;
use egui::{Align2, Color32, FontFamily, FontId, Rect, RichText, Sense, Stroke};

pub const GREEN: Color32 = Color32::from_rgb(80, 210, 80);
pub const BLUE: Color32 = Color32::from_rgb(100, 180, 255);
pub const RED: Color32 = Color32::from_rgb(220, 60, 60);
pub const ORANGE: Color32 = Color32::from_rgb(230, 160, 0);

/// Семейство с жирным начертанием Terminus.
pub fn bold() -> FontFamily {
    FontFamily::Name("terminus_bold".into())
}

pub fn setup(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    fonts.font_data.insert(
        "terminus".into(),
        egui::FontData::from_static(include_bytes!("../assets/Terminus__TTF__500.ttf")),
    );
    fonts.font_data.insert(
        "terminus_bold".into(),
        egui::FontData::from_static(include_bytes!("../assets/Terminus__TTF__Bold_700.ttf")),
    );

    fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "terminus".into());
    fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "terminus".into());

    // жирное семейство: Bold первым, дальше обычная цепочка как запасная (значки и т.п.)
    let mut bold_chain = vec!["terminus_bold".to_owned()];
    if let Some(chain) = fonts.families.get(&FontFamily::Proportional) {
        bold_chain.extend(chain.iter().cloned());
    }
    fonts.families.insert(bold(), bold_chain);

    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();
    let black = Color32::BLACK;
    let white = Color32::WHITE;
    let gray05 = Color32::from_gray(12);
    let gray10 = Color32::from_gray(22);
    let gray20 = Color32::from_gray(45);

    visuals.override_text_color = Some(white);
    visuals.panel_fill = black;
    visuals.window_fill = black;
    visuals.extreme_bg_color = black;
    visuals.faint_bg_color = gray05;

    for w in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        w.bg_fill = gray10;
        w.weak_bg_fill = gray05;
        w.fg_stroke = Stroke::new(1.0_f32, white);
        w.bg_stroke = Stroke::new(1.0_f32, gray20);
    }
    visuals.widgets.hovered.bg_fill = gray20;
    visuals.widgets.active.bg_fill = gray20;
    visuals.widgets.hovered.expansion = 0.0;
    visuals.widgets.active.expansion = 0.0;

    visuals.selection.bg_fill = Color32::from_rgb(0, 80, 160);
    visuals.selection.stroke = Stroke::new(1.0_f32, white);
    visuals.striped = true;

    ctx.set_visuals(visuals);
}

/// Кнопка-контур: цветная рамка и текст, при наведении — заливка цветом и чёрный текст.
pub fn outline_button(ui: &mut egui::Ui, label: &str, color: Color32, enabled: bool, w: f32, h: f32) -> egui::Response {
    let color = if enabled { color } else { Color32::from_gray(90) };
    let btn = ui.add_sized(
        [w, h],
        egui::Button::new(RichText::new(label).size(14.0).color(color))
            .fill(Color32::from_gray(22))
            .stroke(Stroke::new(1.0_f32, color))
            .sense(if enabled { Sense::click() } else { Sense::hover() }),
    );
    if enabled && btn.hovered() {
        let painter = ui.painter();
        painter.rect_filled(btn.rect, 2.0, color);
        painter.rect_stroke(btn.rect, 2.0, Stroke::new(1.0_f32, color));
        painter.text(
            btn.rect.center(),
            Align2::CENTER_CENTER,
            label,
            FontId::proportional(14.0),
            Color32::BLACK,
        );
    }
    btn
}

/// Сплошная кнопка с заливкой (главное действие). Неактивная — серая.
pub fn solid_button(
    ui: &mut egui::Ui,
    label: &str,
    color: Color32,
    hover: Color32,
    enabled: bool,
    w: f32,
    h: f32,
) -> egui::Response {
    let fill = if enabled { color } else { Color32::from_gray(50) };
    let text_color = if enabled { Color32::BLACK } else { Color32::from_gray(140) };

    let btn = ui.add_sized(
        [w, h],
        egui::Button::new(RichText::new(label).size(14.0).family(bold()).color(text_color))
            .fill(fill)
            .stroke(Stroke::new(0.0_f32, fill))
            .sense(if enabled { Sense::click() } else { Sense::hover() }),
    );
    if enabled && btn.hovered() {
        ui.painter().rect_filled(btn.rect, 4.0, hover);
        ui.painter().text(
            btn.rect.center(),
            Align2::CENTER_CENTER,
            label,
            FontId::new(14.0, bold()),
            Color32::BLACK,
        );
    }
    btn
}

/// Главная кнопка в виде контура (жирный текст): по умолчанию тёмная с цветной рамкой и текстом,
/// при наведении заливается цветом, текст становится чёрным. Неактивная — серая.
pub fn ghost_button(ui: &mut egui::Ui, label: &str, color: Color32, enabled: bool, w: f32, h: f32) -> egui::Response {
    let color = if enabled { color } else { Color32::from_gray(90) };
    let btn = ui.add_sized(
        [w, h],
        egui::Button::new(RichText::new(label).size(14.0).family(bold()).color(color))
            .fill(Color32::from_gray(22))
            .stroke(Stroke::new(1.0_f32, color))
            .sense(if enabled { Sense::click() } else { Sense::hover() }),
    );
    if enabled && btn.hovered() {
        let painter = ui.painter();
        painter.rect_filled(btn.rect, 4.0, color);
        painter.text(
            btn.rect.center(),
            Align2::CENTER_CENTER,
            label,
            FontId::new(14.0, bold()),
            Color32::BLACK,
        );
    }
    btn
}

/// Маленькая кнопка-значок (стрелка, домик): по умолчанию обычная, при наведении фон белый, значок чёрный.
pub fn icon_button(ui: &mut egui::Ui, icon: &str, tooltip: &str) -> egui::Response {
    let btn = ui.button(RichText::new(icon).size(14.0)).on_hover_text(tooltip);
    if btn.hovered() {
        let painter = ui.painter();
        painter.rect_filled(btn.rect, 2.0, Color32::WHITE);
        painter.text(
            btn.rect.center(),
            Align2::CENTER_CENTER,
            icon,
            FontId::proportional(14.0),
            Color32::BLACK,
        );
    }
    btn
}

/// Подпись поля формы.
pub fn field_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(13.0));
}

/// Мелкая серая подпись / подсказка.
pub fn caption(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).monospace().size(11.0).color(Color32::from_gray(140)));
}

/// Прогресс-бар в стиле AverStor. `fraction = None` — размер неизвестен,
/// по полосе ходит бегунок. `label_color` — цвет подписи под полосой; длинная подпись
/// (например, текст ошибки) переносится на следующие строки.
pub fn progress_bar(
    ui: &mut egui::Ui,
    fraction: Option<f32>,
    color: Color32,
    label: &str,
    label_color: Color32,
) -> egui::Response {
    let bar_h = 10.0_f32;
    let gap = 3.0_f32;
    let bar_w = (ui.available_width() - 8.0).max(20.0);
    let time = ui.input(|i| i.time) as f32;

    let (bar_rect, response) = ui.allocate_exact_size(egui::vec2(bar_w, bar_h), Sense::hover());
    let painter = ui.painter();

    painter.rect_filled(bar_rect, 3.0, Color32::from_gray(30));
    match fraction {
        Some(f) => {
            let f = f.clamp(0.0, 1.0);
            if f > 0.0 {
                let filled = Rect::from_min_size(bar_rect.min, egui::vec2(bar_w * f, bar_h));
                painter.rect_filled(filled, 3.0, color);
            }
        }
        None => {
            let seg = bar_w * 0.25;
            let phase = (time * 0.8) % 2.0;
            let pos = if phase < 1.0 { phase } else { 2.0 - phase };
            let x = bar_rect.min.x + (bar_w - seg) * pos;
            let r = Rect::from_min_size(egui::pos2(x, bar_rect.min.y), egui::vec2(seg, bar_h));
            painter.rect_filled(r, 3.0, color);
        }
    }
    painter.rect_stroke(bar_rect, 3.0, Stroke::new(1.0_f32, Color32::from_gray(50)));

    ui.add_space(gap);
    ui.label(RichText::new(label).monospace().size(11.0).color(label_color));

    response
}
