use crate::history::History;
use crate::tftp;
use crate::theme;
use eframe::egui;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Сообщения из фоновых потоков в GUI-поток.
enum WorkerMsg {
    Log(String),
    Progress(u64, Option<u64>),
    Done(Result<(), String>),
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Receive,
    Send,
}

type Found = Vec<(IpAddr, String)>;

/// Как часто обновлять список устройств, пока открыта вкладка «Отправить».
const SCAN_INTERVAL: Duration = Duration::from_secs(3);

/// Куда вернуть результат встроенного диалога выбора.
#[derive(Clone, Copy, PartialEq)]
enum PickTarget {
    Send,    // что отправлять: файл или папка
    RecvDir, // куда принимать: только папка
}

struct Entry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

/// Встроенный (нарисованный средствами egui) диалог выбора файла или папки.
/// Не зависит от GTK, xdg-portal и прочих системных диалогов, поэтому работает везде одинаково.
struct Picker {
    target: PickTarget,
    dir: PathBuf,
    path_input: String,
    /// Выделенные элементы текущей папки (для приёма — не больше одной папки).
    selected: Vec<PathBuf>,
    /// Индекс последнего выделенного кликом элемента: от него считается диапазон по Shift+клик.
    anchor: Option<usize>,
    show_hidden: bool,
    entries: Vec<Entry>,
    error: Option<String>,
}

impl Picker {
    fn new(target: PickTarget, start: PathBuf) -> Self {
        let mut p = Picker {
            target,
            dir: start.clone(),
            path_input: String::new(),
            selected: Vec::new(),
            anchor: None,
            show_hidden: false,
            entries: Vec::new(),
            error: None,
        };
        p.go(start);
        p
    }

    fn only_dirs(&self) -> bool {
        self.target == PickTarget::RecvDir
    }

    /// Несколько элементов можно выбрать только при выборе того, что отправлять.
    fn multi(&self) -> bool {
        self.target == PickTarget::Send
    }

    /// Переходит в папку и перечитывает содержимое. Если передан путь к файлу — открывает его папку
    /// и выделяет файл. При ошибке остаётся в текущей папке и показывает причину.
    fn go(&mut self, dir: PathBuf) {
        if dir.is_file() && !self.only_dirs() {
            if let Some(parent) = dir.parent() {
                let file = dir.clone();
                self.go(parent.to_path_buf());
                self.selected = vec![file];
            }
            return;
        }
        match std::fs::read_dir(&dir) {
            Ok(rd) => {
                let mut entries = Vec::new();
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if !self.show_hidden && name.starts_with('.') {
                        continue;
                    }
                    let path = e.path();
                    let Ok(md) = std::fs::metadata(&path) else {
                        continue; // битая ссылка, нет доступа
                    };
                    let is_dir = md.is_dir();
                    if !is_dir && (self.only_dirs() || !md.is_file()) {
                        continue;
                    }
                    entries.push(Entry { name, path, is_dir, size: md.len() });
                }
                entries.sort_by(|a, b| {
                    b.is_dir
                        .cmp(&a.is_dir)
                        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                });
                self.dir = dir.canonicalize().unwrap_or(dir);
                self.entries = entries;
                self.selected.clear();
                self.anchor = None;
                self.error = None;
            }
            Err(e) => self.error = Some(format!("Не удалось открыть {}: {e}", dir.display())),
        }
        self.path_input = self.dir.display().to_string();
    }

    /// Клик по элементу `i` списка: обычный — выбрать только его; Ctrl — добавить/убрать;
    /// Shift — диапазон от последнего выбранного кликом. Для выбора папки приёма — всегда один.
    fn apply_click(&mut self, entries: &[Entry], i: usize, toggle: bool, range: bool) {
        let multi = self.multi();
        match self.anchor {
            Some(a) if multi && range => {
                let (lo, hi) = (a.min(i), a.max(i));
                self.selected = entries[lo..=hi].iter().map(|x| x.path.clone()).collect();
            }
            _ if multi && toggle => {
                let path = &entries[i].path;
                if let Some(pos) = self.selected.iter().position(|q| q == path) {
                    self.selected.remove(pos);
                } else {
                    self.selected.push(path.clone());
                }
                self.anchor = Some(i);
            }
            _ => {
                self.selected = vec![entries[i].path.clone()];
                self.anchor = Some(i);
            }
        }
    }

    /// Some(Some(пути)) — выбрано, Some(None) — отмена, None — диалог ещё открыт.
    fn ui(&mut self, ui: &mut egui::Ui) -> Option<Option<Vec<PathBuf>>> {
        let mut out: Option<Option<Vec<PathBuf>>> = None;
        let mut goto: Option<PathBuf> = None;
        let multi = self.multi();

        ui.horizontal(|ui| {
            if theme::icon_button(ui, "⬆", "Вверх").clicked() {
                if let Some(p) = self.dir.parent() {
                    goto = Some(p.to_path_buf());
                }
            }
            if theme::icon_button(ui, "🏠", "Домой").clicked() {
                if let Some(h) = dirs::home_dir() {
                    goto = Some(h);
                }
            }
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.path_input)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(ui.available_width().max(100.0)),
            );
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                goto = Some(PathBuf::from(self.path_input.trim()));
            }
        });
        ui.horizontal(|ui| {
            if ui.checkbox(&mut self.show_hidden, "показывать скрытые").changed() {
                goto = Some(self.dir.clone());
            }
            if multi {
                ui.add_space(10.0);
                if theme::outline_button(ui, "Выделить всё", theme::BLUE, !self.entries.is_empty(), 120.0, 22.0)
                    .clicked()
                {
                    self.selected = self.entries.iter().map(|e| e.path.clone()).collect();
                }
            }
        });
        if multi {
            theme::caption(ui, "Ctrl+клик — добавить или убрать, Shift+клик — диапазон");
        }
        if let Some(err) = &self.error {
            ui.label(egui::RichText::new(err.as_str()).size(12.0).color(theme::RED));
        }
        ui.separator();

        let entries = std::mem::take(&mut self.entries);
        egui::ScrollArea::vertical()
            .max_height(260.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if entries.is_empty() {
                    theme::caption(ui, "пусто");
                }
                for (i, e) in entries.iter().enumerate() {
                    let text = if e.is_dir {
                        format!("{}/", e.name)
                    } else {
                        format!("{}   {}", e.name, fmt_bytes(e.size))
                    };
                    let is_sel = self.selected.contains(&e.path);
                    let resp = ui.selectable_label(is_sel, text);
                    if resp.clicked() {
                        let (toggle, range) = ui.input(|inp| (inp.modifiers.command, inp.modifiers.shift));
                        self.apply_click(&entries, i, toggle, range);
                    }
                    if resp.double_clicked() {
                        if e.is_dir {
                            goto = Some(e.path.clone()); // войти в папку
                        } else {
                            out = Some(Some(vec![e.path.clone()])); // файл выбран
                        }
                    }
                }
            });
        self.entries = entries;

        ui.separator();
        // Ничего не выделено — выбирается текущая открытая папка целиком.
        let chosen: Vec<PathBuf> = if self.selected.is_empty() {
            vec![self.dir.clone()]
        } else {
            self.selected.clone()
        };
        ui.label(
            egui::RichText::new(format!("Будет выбрано: {}", paths_summary(&chosen)))
                .monospace()
                .size(12.0),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if theme::ghost_button(ui, "Выбрать", theme::GREEN, true, 110.0, 28.0).clicked() {
                out = Some(Some(chosen.clone()));
            }
            if theme::outline_button(ui, "Отмена", egui::Color32::from_gray(170), true, 110.0, 28.0).clicked() {
                out = Some(None);
            }
        });

        if let Some(d) = goto {
            self.go(d);
        }
        out
    }
}

/// Порт для приёма, отправки и поиска устройств. Один на всех: >1024, чтобы не требовался root.
const PORT: u16 = 6969;

pub struct TftpApp {
    tab: Tab,

    // ---- вкладка «Отправить» ----
    host: String,
    local_paths: Vec<PathBuf>,
    /// Текст в поле пути (путь можно вставить руками — работает без диалога и drag&drop).
    /// Если выбрано несколько элементов, здесь их краткий список, и поле только для чтения.
    local_input: String,
    history: History,
    found: Found,
    scan_rx: Option<Receiver<Found>>,
    last_scan: Instant,
    /// true — получателя вписали руками или выбрали из «недавних»: авто-выбор верхней строки не трогает.
    host_edited: bool,

    // ---- вкладка «Получить» ----
    recv_dir: String,
    recv_stop: Option<Arc<AtomicBool>>,
    my_ips: Vec<String>,

    /// Флаг остановки текущей отправки (Some, пока отправка идёт).
    send_stop: Option<Arc<AtomicBool>>,

    // встроенный диалог выбора файла/папки
    picker: Option<Picker>,

    // состояние текущей операции (отправка или приём)
    busy: bool,
    progress_bytes: u64,
    progress_total: Option<u64>,
    log_lines: Vec<String>,
    /// false — журнал закрыт крестиком; остаётся закрытым до следующего запуска программы.
    log_open: bool,
    rx: Option<Receiver<WorkerMsg>>,
    last_ok: Option<bool>, // итог последней операции: None — ещё не было / идёт
    /// Причина последней неудачи (показывается красной надписью под полосой).
    last_error: Option<String>,
    /// Последняя ошибка, о которой сообщил приём, пока он продолжает работать
    /// (например, один файл не принят): приём не останавливается, но ошибку видно сразу.
    live_error: Option<String>,
}

impl Default for TftpApp {
    fn default() -> Self {
        let history = History::load();
        // прошлая папка приёма, если она ещё существует; иначе домашняя
        let recv_dir = history
            .recv_dir
            .clone()
            .filter(|d| Path::new(d).is_dir())
            .or_else(|| {
                dirs::home_dir()
                    .or_else(|| std::env::current_dir().ok())
                    .map(|p| p.display().to_string())
            })
            .unwrap_or_default();
        Self {
            tab: Tab::Receive,
            host: String::new(),
            local_paths: Vec::new(),
            local_input: String::new(),
            history,
            found: Vec::new(),
            scan_rx: None,
            last_scan: Instant::now(),
            host_edited: false,
            recv_dir,
            recv_stop: None,
            send_stop: None,
            my_ips: tftp::local_ips().into_iter().map(|(_, ip)| ip.to_string()).collect(),
            picker: None,
            busy: false,
            progress_bytes: 0,
            progress_total: None,
            log_lines: Vec::new(),
            log_open: true,
            rx: None,
            last_ok: None,
            last_error: None,
            live_error: None,
        }
    }
}

impl TftpApp {
    fn push_log(&mut self, line: String) {
        self.log_lines.push(line);
        if self.log_lines.len() > 2000 {
            self.log_lines.drain(0..500);
        }
    }

    /// Ошибка до запуска операции (не выбран файл, нет папки и т.п.): в журнал и красной надписью под полосой.
    fn fail(&mut self, msg: String) {
        self.push_log(format!("Ошибка: {msg}"));
        self.last_error = Some(msg);
        self.last_ok = Some(false);
        self.progress_bytes = 0;
        self.progress_total = None;
    }

    fn switch_tab(&mut self, tab: Tab) {
        if self.tab == tab {
            return;
        }
        self.tab = tab;
        self.log_lines.clear();
        self.progress_bytes = 0;
        self.progress_total = None;
        self.last_ok = None;
        self.last_error = None;
        self.live_error = None;
        if tab == Tab::Send {
            self.start_scan();
        }
    }

    // ---------------- встроенный диалог выбора ----------------

    fn open_picker(&mut self, target: PickTarget) {
        if self.picker.is_some() {
            return;
        }
        let home = || {
            dirs::home_dir()
                .or_else(|| std::env::current_dir().ok())
                .unwrap_or_else(|| PathBuf::from("."))
        };
        let start = match target {
            PickTarget::Send => self
                .local_paths
                .first()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .filter(|d| d.is_dir())
                .unwrap_or_else(home),
            PickTarget::RecvDir => {
                let d = PathBuf::from(self.recv_dir.trim());
                if d.is_dir() {
                    d
                } else {
                    home()
                }
            }
        };
        self.picker = Some(Picker::new(target, start));
    }

    fn draw_picker(&mut self, ctx: &egui::Context) {
        let Some(mut picker) = self.picker.take() else {
            return;
        };
        let title = if picker.target == PickTarget::RecvDir {
            "Выберите папку"
        } else {
            "Выберите файлы или папки"
        };
        let mut result: Option<Option<Vec<PathBuf>>> = None;
        egui::Window::new(title)
            .id(egui::Id::new("picker_window"))
            .collapsible(false)
            .resizable(true)
            .default_size([560.0, 420.0])
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                result = picker.ui(ui);
            });
        match result {
            Some(Some(paths)) => match picker.target {
                PickTarget::Send => self.set_local_paths(paths),
                PickTarget::RecvDir => {
                    if let Some(path) = paths.first() {
                        self.recv_dir = path.display().to_string();
                        self.history.set_recv_dir(&self.recv_dir);
                    }
                }
            },
            Some(None) => {}
            None => self.picker = Some(picker),
        }
    }

    /// Единая точка выбора того, что отправлять (кнопки и drag&drop): файлы и папки.
    fn set_local_paths(&mut self, paths: Vec<PathBuf>) {
        self.local_input = paths_summary(&paths);
        self.local_paths = paths;
    }

    fn handle_dropped(&mut self, files: Vec<egui::DroppedFile>) {
        if self.busy || self.picker.is_some() {
            self.push_log("Файл проигнорирован: идёт передача или открыт диалог выбора".into());
            return;
        }
        let paths: Vec<PathBuf> = files.into_iter().filter_map(|f| f.path).collect();
        if paths.is_empty() {
            self.fail("система не передала путь к перетащенному файлу".into());
            return;
        }
        let (existing, missing): (Vec<PathBuf>, Vec<PathBuf>) = paths.into_iter().partition(|p| p.exists());
        if existing.is_empty() {
            for p in &missing {
                self.fail(format!("{} не существует", p.display()));
            }
            return;
        }
        self.switch_tab(Tab::Send);
        for p in &missing {
            self.push_log(format!("Пропущено (не существует): {}", p.display()));
        }
        self.push_log(format!("Выбрано перетаскиванием: {}", paths_summary(&existing)));
        self.set_local_paths(existing);
    }

    // ---------------- поиск устройств ----------------

    fn start_scan(&mut self) {
        if self.scan_rx.is_some() {
            return;
        }
        self.last_scan = Instant::now();
        let (tx, rx) = channel();
        self.scan_rx = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(tftp::discover(PORT, Duration::from_millis(1500)));
        });
    }

    /// Что показываем в таблице: адреса 192.168.* сверху, все остальные ниже
    /// (порядок внутри каждой группы сохраняется).
    fn visible_found(&self) -> Found {
        let is_lan = |ip: &IpAddr| matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 192 && v4.octets()[1] == 168);
        let mut list = self.found.clone();
        list.sort_by_key(|(ip, _)| !is_lan(ip)); // сортировка стабильная: false (192.168) идёт первым
        list
    }

    /// Автообновление списка устройств, пока открыта вкладка «Отправить».
    fn auto_scan(&mut self, ctx: &egui::Context) {
        if self.tab != Tab::Send {
            return;
        }
        if self.scan_rx.is_none() && !self.busy && self.last_scan.elapsed() >= SCAN_INTERVAL {
            self.start_scan();
        }
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    fn poll_scan(&mut self) {
        let Some(rx) = &self.scan_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(found) => {
                self.scan_rx = None;
                self.found = found;
                // по умолчанию выбрана верхняя строка таблицы; выбор пользователя не трогаем
                if !self.host_edited {
                    let visible = self.visible_found();
                    let cur_ok = visible.iter().any(|(ip, _)| ip.to_string() == self.host);
                    if !cur_ok {
                        if let Some((ip, _)) = visible.first() {
                            self.host = ip.to_string();
                        }
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => self.scan_rx = None,
        }
    }

    // ---------------- отправка / приём ----------------

    /// Сбрасывает состояние и возвращает канал для фонового потока.
    fn begin_worker(&mut self) -> Sender<WorkerMsg> {
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = true;
        self.last_ok = None;
        self.last_error = None;
        self.live_error = None;
        self.progress_bytes = 0;
        self.progress_total = None;
        self.log_lines.clear();
        tx
    }

    fn start_send(&mut self) {
        if self.local_paths.is_empty() {
            self.fail("не выбран файл или папка".into());
            return;
        }
        if let Some(p) = self.local_paths.iter().find(|p| !p.exists()) {
            let msg = format!("{} не существует", p.display());
            self.fail(msg);
            return;
        }
        let local = self.local_paths.clone();
        let host = self.host.trim().to_string();
        if host.is_empty() {
            self.fail("не указан получатель".into());
            return;
        }
        let port = PORT;
        self.history.push(&host);

        let stop = Arc::new(AtomicBool::new(false));
        self.send_stop = Some(stop.clone());
        let tx = self.begin_worker();
        std::thread::spawn(move || {
            let tx_log = tx.clone();
            let tx_prog = tx.clone();
            let result = tftp::send_paths_cancel(
                &host,
                port,
                &local,
                &stop,
                move |line| {
                    let _ = tx_log.send(WorkerMsg::Log(line.to_string()));
                },
                move |sent, total| {
                    let _ = tx_prog.send(WorkerMsg::Progress(sent, total));
                },
            );
            let _ = tx.send(WorkerMsg::Done(result.map_err(|e| e.to_string())));
        });
    }

    /// «Начать приём»: слушаем порт и принимаем входящие файлы, пока не нажмут «Остановить».
    fn start_receive(&mut self) {
        let port = PORT;
        let dir = PathBuf::from(self.recv_dir.trim());
        if self.recv_dir.trim().is_empty() || !dir.is_dir() {
            self.fail("папка для приёма не существует".into());
            return;
        }
        self.history.set_recv_dir(&self.recv_dir); // в том числе если путь вписан вручную

        let stop = Arc::new(AtomicBool::new(false));
        self.recv_stop = Some(stop.clone());
        // адреса могли поменяться после запуска программы — обновляем при каждом старте
        self.my_ips = tftp::local_ips().into_iter().map(|(_, ip)| ip.to_string()).collect();

        let tx = self.begin_worker();
        std::thread::spawn(move || {
            let tx_log = tx.clone();
            let tx_prog = tx.clone();
            let result = tftp::receive_loop(
                "0.0.0.0",
                port,
                &dir,
                &stop,
                move |line| {
                    let _ = tx_log.send(WorkerMsg::Log(line.to_string()));
                },
                move |recv, total| {
                    let _ = tx_prog.send(WorkerMsg::Progress(recv, total));
                },
            );
            let _ = tx.send(WorkerMsg::Done(result.map_err(|e| e.to_string())));
        });
    }

    /// «Остановить» у отправителя: отправка прекращается сразу, получателю уходит ошибка.
    fn cancel_send(&mut self) {
        if let Some(flag) = &self.send_stop {
            flag.store(true, Ordering::Relaxed);
            self.push_log("Останавливаю отправку…".into());
        }
    }

    /// «Остановить» у получателя: приём прекращается сразу, недокачанное и всё уже принятое удаляется.
    fn cancel_receive(&mut self) {
        if let Some(flag) = &self.recv_stop {
            flag.store(true, Ordering::Relaxed);
            self.push_log("Останавливаю приём, принятые файлы будут удалены…".into());
        }
    }

    fn poll_client(&mut self) {
        let mut finished = false;
        if let Some(rx) = &self.rx {
            let mut got_done = false;
            loop {
                match rx.try_recv() {
                    Ok(WorkerMsg::Log(l)) => {
                        if l.to_lowercase().contains("ошибк") {
                            self.live_error = Some(l.trim().to_string());
                        }
                        self.log_lines.push(l);
                    }
                    Ok(WorkerMsg::Progress(done, total)) => {
                        self.progress_bytes = done;
                        self.progress_total = total;
                    }
                    Ok(WorkerMsg::Done(res)) => {
                        got_done = true;
                        finished = true;
                        let receiving = self.recv_stop.is_some();
                        let user_stopped = self
                            .recv_stop
                            .as_ref()
                            .or(self.send_stop.as_ref())
                            .is_some_and(|f| f.load(Ordering::Relaxed));
                        let ok = res.is_ok();
                        // Остановка пользователем — не ошибка: приём завершается Ok, отправка — ошибкой Cancelled.
                        let stopped_by_user = user_stopped && (receiving == ok);
                        // Приём, остановленный вручную, — не «успех передачи»: полоса возвращается в исходное
                        // состояние. Приём, завершившийся сам (всё принято и проверено), и успешная отправка
                        // оставляют полную зелёную полосу и надпись об успехе, пока не начнётся новое действие
                        // или не сменится вкладка.
                        self.last_ok = if stopped_by_user { None } else { Some(ok) };
                        match res {
                            Ok(()) if receiving && user_stopped => {
                                self.log_lines.push("=== Приём остановлен ===".to_string())
                            }
                            Ok(()) if receiving => self.log_lines.push("=== Приём завершён ===".to_string()),
                            Ok(()) => self.log_lines.push("=== Готово ===".to_string()),
                            Err(_) if stopped_by_user => {
                                self.log_lines.push("=== Отправка остановлена ===".to_string())
                            }
                            Err(e) => {
                                self.log_lines.push(format!("=== Ошибка: {e} ==="));
                                self.last_error = Some(e);
                            }
                        }
                        if ok && !receiving {
                            // как при открытии программы: выбранное уже отправлено, поле пути пустое
                            self.local_paths.clear();
                            self.local_input.clear();
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        if !got_done {
                            self.log_lines
                                .push("=== Поток передачи неожиданно завершился ===".to_string());
                            self.last_error = Some("поток передачи неожиданно завершился".into());
                            self.last_ok = Some(false);
                        }
                        finished = true;
                        break;
                    }
                }
            }
        }
        if finished {
            self.busy = false;
            self.rx = None;
            self.recv_stop = None;
            self.send_stop = None;
        }
        if self.log_lines.len() > 2000 {
            self.log_lines.drain(0..500);
        }
    }
}

impl eframe::App for TftpApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_client();
        self.poll_scan();
        self.auto_scan(ctx);
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(50));
        } else if self.scan_rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        // ---- Drag & drop файла или папки в окно: выбирает, что отправлять ----
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped.is_empty() {
            self.handle_dropped(dropped);
        }

        self.draw_log_panel(ctx);
        self.draw_top(ctx);
        match self.tab {
            Tab::Receive => self.draw_receive(ctx),
            Tab::Send => self.draw_send(ctx),
        }
        self.draw_picker(ctx);
        self.draw_drop_overlay(ctx);
    }
}

impl TftpApp {
    /// Подсказка поверх окна, пока над ним держат файл.
    fn draw_drop_overlay(&self, ctx: &egui::Context) {
        if self.busy || self.picker.is_some() || !ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            return;
        }
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("drop_overlay"),
        ));
        let rect = ctx.screen_rect();
        painter.rect_filled(rect, 0.0, egui::Color32::from_black_alpha(170));
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Отпустите файлы или папки, чтобы отправить",
            egui::FontId::proportional(20.0),
            egui::Color32::WHITE,
        );
    }

    fn draw_top(&mut self, ctx: &egui::Context) {
        let mut want: Option<Tab> = None;
        egui::TopBottomPanel::top("top_panel")
            .frame(
                egui::Frame::default()
                    .fill(ctx.style().visuals.window_fill)
                    .inner_margin(egui::Margin::symmetric(14.0, 0.0)),
            )
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.vertical_centered(|ui| {
                    ui.heading(egui::RichText::new("tftp-rs").size(18.0).family(theme::bold()));
                });
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    for (tab, label) in [(Tab::Receive, "Получить"), (Tab::Send, "Отправить")] {
                        let resp = if self.tab == tab {
                            theme::solid_button(
                                ui,
                                label,
                                egui::Color32::WHITE,
                                egui::Color32::from_gray(225),
                                true,
                                110.0,
                                28.0,
                            )
                        } else {
                            // во время передачи или приёма вкладки не переключаются
                            theme::outline_button(ui, label, egui::Color32::from_gray(170), !self.busy, 110.0, 28.0)
                        };
                        if resp.clicked() {
                            want = Some(tab);
                        }
                    }
                });
                ui.add_space(8.0);
            });
        if let Some(tab) = want {
            if !self.busy {
                self.switch_tab(tab);
            }
        }
    }

    /// Плавающий журнал поверх интерфейса (как в AverStor).
    fn draw_log_panel(&mut self, ctx: &egui::Context) {
        if !self.log_open {
            return;
        }
        let mut close = false;
        egui::Window::new("")
            .id(egui::Id::new("log_panel"))
            .title_bar(false)
            .resizable(true)
            .default_height(160.0)
            .default_width(520.0)
            .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -8.0))
            .show(ctx, |ui| {
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    theme::caption(ui, "журнал");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::icon_button(ui, "×", "Закрыть журнал").clicked() {
                            close = true;
                        }
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .max_height(300.0)
                    .show(ui, |ui| {
                        for line in &self.log_lines {
                            ui.label(
                                egui::RichText::new(line.as_str())
                                    .monospace()
                                    .size(12.0)
                                    .color(log_color(line)),
                            );
                        }
                    });
            });
        if close {
            self.log_open = false;
        }
    }

    // ---------------- вкладка «Получить» ----------------

    fn draw_receive(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            let receiving = self.recv_stop.is_some();
            // Some(true) — остановка запрошена, ждём завершения текущего файла
            let stopping = self.recv_stop.as_ref().map(|f| f.load(Ordering::Relaxed));

            egui::Grid::new("recv_grid")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    theme::field_label(ui, "Папка приёма");
                    ui.horizontal(|ui| {
                        let can_pick = !self.busy && self.picker.is_none();
                        if theme::outline_button(ui, "Выбрать…", theme::BLUE, can_pick, 110.0, 26.0).clicked() {
                            self.open_picker(PickTarget::RecvDir);
                        }
                        ui.add_enabled(
                            !receiving,
                            egui::TextEdit::singleline(&mut self.recv_dir)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(280.0),
                        );
                    });
                    ui.end_row();
                });

            ui.add_space(18.0);
            ui.horizontal(|ui| {
                match stopping {
                    None => {
                        let can = !self.busy && self.picker.is_none();
                        if theme::ghost_button(ui, "Начать приём", theme::GREEN, can, 150.0, 34.0)
                            .clicked()
                        {
                            self.start_receive();
                        }
                    }
                    Some(false) => {
                        if theme::ghost_button(ui, "Остановить", theme::RED, true, 150.0, 34.0).clicked() {
                            self.cancel_receive();
                        }
                    }
                    Some(true) => {
                        theme::ghost_button(ui, "Остановка…", theme::RED, false, 150.0, 34.0);
                    }
                }
                if self.busy {
                    ui.add_space(8.0);
                    ui.spinner();
                }
            });

            if receiving {
                ui.add_space(14.0);
                theme::caption(ui, "Сообщите отправителю адрес:");
                if self.my_ips.is_empty() {
                    ui.label(
                        egui::RichText::new("сетевой адрес не найден — проверьте кабель и настройки сети")
                            .color(theme::ORANGE),
                    );
                }
                for ip in &self.my_ips {
                    ui.label(
                        egui::RichText::new(ip.as_str())
                            .monospace()
                            .size(18.0)
                            .color(theme::GREEN),
                    );
                }
            }

            ui.add_space(18.0);
            self.draw_progress(ui);
        });
    }

    // ---------------- вкладка «Отправить» ----------------

    fn draw_send(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);

            egui::Grid::new("send_grid")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    theme::field_label(ui, "Что отправить");
                    ui.horizontal(|ui| {
                        let idle = !self.busy && self.picker.is_none();
                        if theme::outline_button(ui, "Выбрать…", theme::BLUE, idle, 110.0, 26.0).clicked() {
                            self.open_picker(PickTarget::Send);
                        }
                        // при выборе нескольких элементов поле показывает их список и не редактируется
                        let editable = self.local_paths.len() <= 1;
                        let resp = ui.add_enabled(
                            editable,
                            egui::TextEdit::singleline(&mut self.local_input)
                                .hint_text("путь или перетащите файлы в окно")
                                .font(egui::TextStyle::Monospace)
                                .desired_width(220.0),
                        );
                        if resp.changed() {
                            let t = self.local_input.trim().to_string();
                            self.local_paths = if t.is_empty() { Vec::new() } else { vec![PathBuf::from(t)] };
                        }
                    });
                    ui.end_row();

                    theme::field_label(ui, "Получатель");
                    ui.vertical(|ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.host)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(250.0),
                        );
                        if resp.changed() {
                            self.host_edited = true;
                        }

                        ui.add_space(4.0);
                        let visible = self.visible_found();
                        egui::ScrollArea::vertical()
                            .id_salt("devices_scroll")
                            .max_height(110.0)
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                if visible.is_empty() {
                                    theme::caption(ui, "никого нет: на другом устройстве нажмите «Начать приём»");
                                }
                                ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                                    for (ip, name) in &visible {
                                        let ip_s = ip.to_string();
                                        let text = if name.is_empty() {
                                            ip_s.clone()
                                        } else {
                                            format!("{ip_s}   {name}")
                                        };
                                        if ui.selectable_label(self.host == ip_s, text).clicked() {
                                            self.host = ip_s;
                                            self.host_edited = false;
                                        }
                                    }
                                });
                            });

                        let entries = self.history.entries.clone();
                        if !entries.is_empty() {
                            ui.add_space(6.0);
                            theme::caption(ui, "недавние");
                            for entry in entries {
                                ui.horizontal(|ui| {
                                    if ui.selectable_label(false, entry.as_str()).clicked() {
                                        self.host = entry.clone();
                                        self.host_edited = true;
                                    }
                                    if ui.small_button("×").clicked() {
                                        self.history.remove(&entry);
                                    }
                                });
                            }
                        }
                    });
                    ui.end_row();
                });

            ui.add_space(18.0);
            ui.horizontal(|ui| {
                let idle = !self.busy && self.picker.is_none();
                let can_send = idle && !self.host.trim().is_empty() && !self.local_paths.is_empty();
                // Some(false) — идёт отправка, Some(true) — остановка запрошена
                match self.send_stop.as_ref().map(|f| f.load(Ordering::Relaxed)) {
                    None => {
                        if theme::ghost_button(ui, "Отправить", theme::GREEN, can_send, 150.0, 34.0)
                            .clicked()
                        {
                            self.start_send();
                        }
                    }
                    Some(false) => {
                        if theme::ghost_button(ui, "Остановить", theme::RED, true, 150.0, 34.0).clicked() {
                            self.cancel_send();
                        }
                    }
                    Some(true) => {
                        theme::ghost_button(ui, "Остановка…", theme::RED, false, 150.0, 34.0);
                    }
                }
                if self.busy {
                    ui.add_space(8.0);
                    ui.spinner();
                }
            });

            ui.add_space(18.0);
            self.draw_progress(ui);
        });
    }

    /// Полоса прогресса; под ней — красная надпись, если приём в процессе получил ошибку
    /// (сама передача при этом идёт дальше).
    fn draw_progress(&self, ui: &mut egui::Ui) {
        let (fraction, color, label, label_color) = self.progress_view();
        theme::progress_bar(ui, fraction, color, &label, label_color);
        if self.busy {
            if let Some(e) = &self.live_error {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(error_label(e))
                        .monospace()
                        .size(11.0)
                        .color(theme::RED),
                );
            }
        }
    }

    /// (доля заполнения или None для «размер неизвестен», цвет полосы, подпись, цвет подписи)
    fn progress_view(&self) -> (Option<f32>, egui::Color32, String, egui::Color32) {
        let gray = egui::Color32::from_gray(160);
        let done = self.progress_bytes;
        let total = self.progress_total.filter(|t| *t > 0);
        let ratio = total.map(|t| (done as f32 / t as f32).clamp(0.0, 1.0));
        let label = match total {
            Some(t) => format!(
                "{} / {}  ({:.0}%)",
                fmt_bytes(done),
                fmt_bytes(t),
                ratio.unwrap_or(0.0) * 100.0
            ),
            None => format!("{}  (общий размер неизвестен)", fmt_bytes(done)),
        };
        let label = if self.recv_stop.is_some() && done == 0 {
            "ожидание файлов…".to_string()
        } else {
            label
        };
        if self.busy {
            return (ratio, theme::GREEN, label, gray);
        }
        match self.last_ok {
            Some(true) => {
                let verb = if self.tab == Tab::Receive { "Успешно получено" } else { "Успешно передано" };
                (Some(1.0), theme::GREEN, format!("{verb}  ·  {}", fmt_bytes(done)), theme::GREEN)
            }
            Some(false) => match &self.last_error {
                Some(e) => (Some(ratio.unwrap_or(0.0)), theme::RED, error_label(e), theme::RED),
                None => (Some(ratio.unwrap_or(0.0)), theme::RED, label, gray),
            },
            None => (Some(0.0), theme::GREEN, "готов к работе".to_string(), gray),
        }
    }
}

/// Краткое описание выбранного: один путь целиком, несколько — «3 шт.: a.bin, b.txt, docs».
fn paths_summary(paths: &[PathBuf]) -> String {
    match paths {
        [] => String::new(),
        [one] => short_path(one),
        many => {
            let names: Vec<String> = many
                .iter()
                .take(3)
                .map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string()))
                .collect();
            let more = if many.len() > 3 { ", …" } else { "" };
            format!("{} шт.: {}{more}", many.len(), names.join(", "))
        }
    }
}

/// Длинный путь → «…хвост», чтобы влезал в строку.
fn short_path(p: &Path) -> String {
    const MAX: usize = 60;
    let s = p.display().to_string();
    let n = s.chars().count();
    if n <= MAX {
        s
    } else {
        let tail: String = s.chars().skip(n - (MAX - 1)).collect();
        format!("…{tail}")
    }
}

/// «Ошибка: причина»; если сама причина уже начинается со слова «Ошибка», приставка не нужна.
fn error_label(e: &str) -> String {
    if e.starts_with("Ошибка") {
        e.to_string()
    } else {
        format!("Ошибка: {e}")
    }
}

fn fmt_bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let f = n as f64;
    if f < K {
        format!("{n} Б")
    } else if f < K * K {
        format!("{:.1} КБ", f / K)
    } else if f < K * K * K {
        format!("{:.1} МБ", f / (K * K))
    } else {
        format!("{:.2} ГБ", f / (K * K * K))
    }
}

fn log_color(line: &str) -> egui::Color32 {
    let low = line.to_lowercase();
    if low.contains("ошибк") {
        theme::RED
    } else if low.contains("таймаут") || low.contains("пропущено") {
        theme::ORANGE
    } else if low.contains('✓') || low.contains("готово") {
        theme::GREEN
    } else {
        egui::Color32::WHITE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(names: &[&str]) -> Vec<Entry> {
        names
            .iter()
            .map(|n| Entry { name: n.to_string(), path: PathBuf::from(format!("/d/{n}")), is_dir: false, size: 1 })
            .collect()
    }

    fn picker(target: PickTarget) -> Picker {
        Picker::new(target, std::env::temp_dir())
    }

    fn sel(p: &Picker) -> Vec<String> {
        p.selected.iter().map(|x| x.file_name().unwrap().to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn picker_click_ctrl_and_shift() {
        let e = entries(&["a", "b", "c", "d", "e"]);
        let mut p = picker(PickTarget::Send);
        p.apply_click(&e, 1, false, false); // b
        assert_eq!(sel(&p), ["b"]);
        p.apply_click(&e, 3, true, false); // + d
        assert_eq!(sel(&p), ["b", "d"]);
        p.apply_click(&e, 1, true, false); // − b
        assert_eq!(sel(&p), ["d"]);
        p.apply_click(&e, 0, false, false); // обычный клик сбрасывает выбор
        assert_eq!(sel(&p), ["a"]);
        p.apply_click(&e, 3, false, true); // Shift: a..d
        assert_eq!(sel(&p), ["a", "b", "c", "d"]);
        p.apply_click(&e, 1, false, true); // Shift от той же опоры: a..b
        assert_eq!(sel(&p), ["a", "b"]);
    }

    #[test]
    fn picker_for_receive_dir_is_single_choice() {
        let e = entries(&["a", "b", "c"]);
        let mut p = picker(PickTarget::RecvDir);
        p.apply_click(&e, 0, false, false);
        p.apply_click(&e, 2, true, false); // Ctrl не добавляет
        assert_eq!(sel(&p), ["c"]);
        p.apply_click(&e, 0, false, true); // Shift не расширяет
        assert_eq!(sel(&p), ["a"]);
    }

    #[test]
    fn summary_of_selection() {
        let p = |s: &str| PathBuf::from(s);
        assert_eq!(paths_summary(&[]), "");
        assert_eq!(paths_summary(&[p("/x/y.bin")]), "/x/y.bin");
        assert_eq!(paths_summary(&[p("/x/a"), p("/x/b")]), "2 шт.: a, b");
        assert_eq!(paths_summary(&[p("/x/a"), p("/x/b"), p("/x/c"), p("/x/d")]), "4 шт.: a, b, c, d".replace(", d", ", …"));
    }

    fn app_finished(receiving: bool, user_stopped: bool, ok: bool, tab: Tab) -> TftpApp {
        let mut app = TftpApp::default();
        app.tab = tab;
        app.local_paths = vec![PathBuf::from("/tmp/x")];
        app.local_input = "/tmp/x".into();
        let (tx, rx) = channel();
        app.rx = Some(rx);
        app.busy = true;
        if receiving {
            app.recv_stop = Some(Arc::new(AtomicBool::new(user_stopped)));
        }
        tx.send(WorkerMsg::Progress(2048, Some(2048))).unwrap();
        tx.send(WorkerMsg::Done(if ok { Ok(()) } else { Err("сбой".into()) })).unwrap();
        app.poll_client();
        app
    }

    #[test]
    fn success_state_after_send() {
        let app = app_finished(false, false, true, Tab::Send);
        assert!(!app.busy && app.recv_stop.is_none());
        assert!(app.local_paths.is_empty() && app.local_input.is_empty(), "поле пути сброшено, как при открытии");
        let (fraction, color, label, label_color) = app.progress_view();
        assert_eq!(fraction, Some(1.0));
        assert_eq!(color, theme::GREEN);
        assert_eq!(label_color, theme::GREEN);
        assert!(label.starts_with("Успешно передано"), "{label}");
    }

    #[test]
    fn success_state_after_receive_finished_by_itself() {
        let app = app_finished(true, false, true, Tab::Receive);
        assert!(!app.busy && app.recv_stop.is_none(), "приём возвращён в исходное состояние");
        let (fraction, _, label, label_color) = app.progress_view();
        assert_eq!(fraction, Some(1.0));
        assert_eq!(label_color, theme::GREEN);
        assert!(label.starts_with("Успешно получено"), "{label}");
        assert!(app.log_lines.iter().any(|l| l.contains("Приём завершён")));
    }

    #[test]
    fn manual_stop_and_errors_do_not_show_success() {
        let stopped = app_finished(true, true, true, Tab::Receive);
        let (fraction, _, label, _) = stopped.progress_view();
        assert_eq!((fraction, label.as_str()), (Some(0.0), "готов к работе"));
        let failed = app_finished(false, false, false, Tab::Send);
        let (_, color, _, _) = failed.progress_view();
        assert_eq!(color, theme::RED);
        assert_eq!(failed.local_paths.len(), 1, "при ошибке выбранное не сбрасывается");
    }

    #[test]
    fn errors_are_shown_in_red_under_the_bar() {
        let failed = app_finished(false, false, false, Tab::Send);
        let (_, color, label, label_color) = failed.progress_view();
        assert_eq!((color, label_color), (theme::RED, theme::RED));
        assert_eq!(label, "Ошибка: сбой");
        // ошибка до запуска (не выбран файл) выглядит так же
        let mut app = TftpApp::default();
        app.tab = Tab::Send;
        app.start_send();
        let (fraction, color, label, label_color) = app.progress_view();
        assert_eq!((fraction, color, label_color), (Some(0.0), theme::RED, theme::RED));
        assert_eq!(label, "Ошибка: не выбран файл или папка");
        // «Ошибка протокола: …» не превращается в «Ошибка: Ошибка протокола: …»
        assert_eq!(error_label("Ошибка протокола: x"), "Ошибка протокола: x");
    }

    #[test]
    fn stopped_send_is_not_an_error() {
        let mut app = TftpApp::default();
        app.tab = Tab::Send;
        app.local_paths = vec![PathBuf::from("/tmp/x")];
        let (tx, rx) = channel();
        app.rx = Some(rx);
        app.busy = true;
        app.send_stop = Some(Arc::new(AtomicBool::new(true)));
        tx.send(WorkerMsg::Done(Err("Передача остановлена".into()))).unwrap();
        app.poll_client();
        assert!(!app.busy && app.send_stop.is_none());
        assert_eq!(app.last_ok, None, "остановка — не красная ошибка");
        assert!(app.last_error.is_none());
        assert_eq!(app.local_paths.len(), 1, "выбранное остаётся, можно отправить снова");
        assert!(app.log_lines.iter().any(|l| l.contains("Отправка остановлена")));
    }

    #[test]
    fn receiver_error_while_running_is_shown_in_red() {
        let mut app = TftpApp::default();
        app.tab = Tab::Receive;
        let (tx, rx) = channel();
        app.rx = Some(rx);
        app.busy = true;
        app.recv_stop = Some(Arc::new(AtomicBool::new(false)));
        tx.send(WorkerMsg::Log("Ошибка приёма a.bin: Таймаут: удалённая сторона не отвечает".into())).unwrap();
        app.poll_client();
        assert!(app.busy);
        assert_eq!(app.live_error.as_deref(), Some("Ошибка приёма a.bin: Таймаут: удалённая сторона не отвечает"));
    }

    #[test]
    fn success_stays_until_tab_switch_or_new_action() {
        let mut app = app_finished(false, false, true, Tab::Send);
        assert_eq!(app.last_ok, Some(true));
        app.switch_tab(Tab::Receive);
        assert_eq!(app.last_ok, None);
        let (_, _, label, _) = app.progress_view();
        assert_eq!(label, "готов к работе");
    }
}
