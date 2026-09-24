//! Хранит список недавно использованных TFTP-серверов (только адреса, порт везде один),
//! чтобы не вводить их заново. Файл: ~/.config/tftp-rs/history.json (Linux).
//! Историю из прежнего каталога ~/.config/tftp/ при первом запуске переносим автоматически.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_ENTRIES: usize = 15;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct History {
    pub entries: Vec<String>, // адреса без порта, последний использованный — в начале списка
    #[serde(default)]
    pub recv_dir: Option<String>,
}

fn config_path() -> Option<PathBuf> {
    let base = dirs::config_dir()?; // на Linux: ~/.config
    let mut dir = base.clone();
    dir.push("tftp-rs");
    std::fs::create_dir_all(&dir).ok()?;
    dir.push("history.json");
    // перенос из старого каталога (программа раньше называлась «tftp»)
    if !dir.exists() {
        let old = base.join("tftp").join("history.json");
        if old.is_file() {
            let _ = std::fs::copy(&old, &dir);
        }
    }
    Some(dir)
}

impl History {
    pub fn load() -> Self {
        if let Some(path) = config_path() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(mut h) = serde_json::from_str::<History>(&text) {
                    // старые записи вида "host:port" превращаем в "host", убираем дубликаты
                    let mut clean: Vec<String> = Vec::new();
                    for e in h.entries.drain(..) {
                        let e = strip_port(&e);
                        if !clean.contains(&e) {
                            clean.push(e);
                        }
                    }
                    h.entries = clean;
                    return h;
                }
            }
        }
        History::default()
    }

    pub fn save(&self) {
        if let Some(path) = config_path() {
            if let Ok(text) = serde_json::to_string_pretty(self) {
                let _ = std::fs::write(path, text);
            }
        }
    }

    /// Добавляет запись в начало, убирает дубликаты, обрезает до MAX_ENTRIES.
    pub fn push(&mut self, host: &str) {
        let entry = host.to_string();
        self.entries.retain(|e| e != &entry);
        self.entries.insert(0, entry);
        self.entries.truncate(MAX_ENTRIES);
        self.save();
    }

    pub fn set_recv_dir(&mut self, d: &str) {
        self.recv_dir = Some(d.to_string());
        self.save();
    }

    pub fn remove(&mut self, entry: &str) {
        self.entries.retain(|e| e != entry);
        self.save();
    }
}

/// Убирает порт из записи вида "host:port" (для старых файлов истории).
fn strip_port(entry: &str) -> String {
    match entry.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.parse::<u16>().is_ok() => h.to_string(),
        _ => entry.to_string(),
    }
}
