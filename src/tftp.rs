//! Нативная реализация TFTP по RFC 1350 (режимы octet и netascii), всё на UDP-сокетах,
//! без внешних зависимостей от системной утилиты tftp.
//!
//! Совместимость с обычными TFTP-клиентами и серверами:
//!   * пакеты RRQ/WRQ/DATA/ACK/ERROR и коды ошибок 0–5 — строго по RFC 1350;
//!   * режимы `octet` и `netascii` (CR LF ↔ перевод строки хоста, CR NUL ↔ CR); `mail` устарел
//!     и отклоняется ошибкой 4;
//!   * у каждой передачи свой TID (порт), чужие пакеты отвергаются ошибкой 5;
//!   * дубликаты ACK не вызывают «Sorcerer's Apprentice»; получатель «задерживается» после
//!     последнего ACK и повторяет его, если отправитель прислал последний DATA снова;
//!   * лишние опции в запросе (RFC 2347) игнорируются — сервер отвечает как по RFC 1350.
//!
//! Собственные расширения (проверка целостности BLAKE3, поиск устройств) включаются, только если
//! собеседник сам подтвердил их поддержку. С обычным TFTP-сервером данные идут чистым RFC 1350,
//! никаких служебных запросов и файлов там не появляется.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Cursor, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BLOCK_SIZE: usize = 512;
const RECV_BUF: usize = 2048;
const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRIES: u32 = 5;

/// Текст ERROR-пакета, которым сторона, остановленная пользователем, сообщает об этом собеседнику
/// (чтобы тот не ждал таймаутов, а сразу прекратил передачу).
const CANCEL_MSG: &str = "Transfer cancelled";
/// Как часто ожидание пакета просыпается, чтобы проверить флаг остановки.
const CANCEL_POLL: Duration = Duration::from_millis(100);
/// Флаг остановки, который никогда не выставляется: для вызовов без возможности отмены (сервер, тесты).
static NEVER: AtomicBool = AtomicBool::new(false);

/// Сколько получатель ждёт после последнего ACK: если ACK потерялся, отправитель повторит
/// последний DATA, и на него нужно ответить снова (RFC 1350, раздел 6). Ожидание идёт в фоновом
/// потоке, поэтому следующая передача не задерживается; число таких потоков ограничено.
const DALLY: Duration = Duration::from_secs(4);
const MAX_DALLY_THREADS: usize = 16;
static DALLYING: AtomicUsize = AtomicUsize::new(0);

/// Проверка, что на той стороне наша программа (см. DISCOVER_MAGIC): 3 попытки по полсекунды.
const PROBE_TRIES: u32 = 3;
const PROBE_WAIT: Duration = Duration::from_millis(500);

/// Служебные имена запросов для проверки целостности. Содержат ':' — обычный файл с таким именем
/// получатель всё равно не принял бы, так что с настоящими файлами они не пересекаются.
/// Перед данными отправитель шлёт ОДНУ общую контрольную сумму (BLAKE3) всего, что будет передано,
/// и список файлов (WRQ MANIFEST_NAME), а в конце запрашивает у получателя итог проверки (RRQ RESULT_NAME).
const MANIFEST_NAME: &str = "tftp:manifest:blake3";
const RESULT_NAME: &str = "tftp:result";
const MANIFEST_MAX: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum TftpError {
    Io(std::io::Error),
    Protocol(String),
    Remote(u16, String),
    Timeout,
    /// Передачу остановил пользователь на этой стороне.
    Cancelled,
}

impl std::fmt::Display for TftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TftpError::Io(e) => write!(f, "IO ошибка: {e}"),
            TftpError::Protocol(s) => write!(f, "Ошибка протокола: {s}"),
            TftpError::Remote(0, msg) if msg == CANCEL_MSG => write!(f, "Удалённая сторона отменила передачу"),
            TftpError::Remote(code, msg) => write!(f, "Удалённая сторона вернула ошибку {code}: {msg}"),
            TftpError::Cancelled => write!(f, "Передача остановлена"),
            TftpError::Timeout => write!(f, "Таймаут: удалённая сторона не отвечает"),
        }
    }
}
impl std::error::Error for TftpError {}
impl From<std::io::Error> for TftpError {
    fn from(e: std::io::Error) -> Self {
        TftpError::Io(e)
    }
}

// ---- Opcodes ----
const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;
const OP_OACK: u16 = 6; // RFC 2347; мы опций не запрашиваем, поэтому OACK для нас — ошибка

/// Режим передачи (RFC 1350). `mail` устарел и не поддерживается.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Байты как есть.
    Octet,
    /// Текст: на проводе CR LF — конец строки, CR NUL — одиночный CR.
    Netascii,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Octet => "octet",
            Mode::Netascii => "netascii",
        }
    }

    /// Регистр не важен (RFC 1350: «any combination of upper and lower case»).
    fn parse(s: &str) -> Option<Mode> {
        match s.to_ascii_lowercase().as_str() {
            "octet" => Some(Mode::Octet),
            "netascii" => Some(Mode::Netascii),
            _ => None,
        }
    }
}

fn opcode_of(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

// ============================= Общие помощники =============================

fn build_rq(opcode: u16, filename: &str, mode: Mode) -> Vec<u8> {
    let mut buf = Vec::with_capacity(filename.len() + 16);
    buf.extend_from_slice(&opcode.to_be_bytes());
    buf.extend_from_slice(filename.as_bytes());
    buf.push(0);
    buf.extend_from_slice(mode.as_str().as_bytes());
    buf.push(0);
    buf
}

fn build_ack(block: u16) -> [u8; 4] {
    let mut buf = [0u8; 4];
    buf[0..2].copy_from_slice(&OP_ACK.to_be_bytes());
    buf[2..4].copy_from_slice(&block.to_be_bytes());
    buf
}

fn build_data(block: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&OP_DATA.to_be_bytes());
    buf.extend_from_slice(&block.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn build_error(code: u16, msg: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(msg.len() + 5);
    buf.extend_from_slice(&OP_ERROR.to_be_bytes());
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(msg.as_bytes());
    buf.push(0);
    buf
}

fn parse_error(buf: &[u8]) -> TftpError {
    if buf.len() < 4 {
        return TftpError::Protocol("короткий ERROR-пакет".into());
    }
    let code = u16::from_be_bytes([buf[2], buf[3]]);
    let body = &buf[4..];
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    TftpError::Remote(code, String::from_utf8_lossy(&body[..end]).into_owned())
}

/// Разбор RRQ/WRQ: (имя файла, режим в нижнем регистре).
/// Имя обязано заканчиваться нулём; у режима недостающий завершающий ноль прощаем.
/// Всё, что идёт после режима (опции RFC 2347), игнорируется — так и должен вести себя
/// сервер, не знающий расширений.
fn parse_rq(buf: &[u8]) -> Option<(String, String)> {
    let rest = buf.get(2..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    let filename = String::from_utf8_lossy(&rest[..end]).into_owned();
    let tail = &rest[end + 1..];
    let mode_end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    if mode_end == 0 {
        return None;
    }
    let mode = String::from_utf8_lossy(&tail[..mode_end]).to_lowercase();
    Some((filename, mode))
}

/// Разбирает режим из запроса или сразу отвечает ошибкой 4 (`mail`, неизвестный режим).
/// `Some(mode)` — можно работать.
fn accept_mode(sock: &UdpSocket, to: SocketAddr, mode: &str) -> Option<Mode> {
    if let Some(m) = Mode::parse(mode) {
        return Some(m);
    }
    let msg = if mode.eq_ignore_ascii_case("mail") {
        "Mail mode is obsolete and not supported"
    } else {
        "Unknown transfer mode (supported: octet, netascii)"
    };
    let _ = sock.send_to(&build_error(4, msg), to);
    None
}

/// Сокет для передачи с новым TID. Если сервер слушает `0.0.0.0`, ответы должны уходить с того
/// же адреса, на который клиент слал запрос, иначе клиенты, проверяющие адрес отправителя,
/// отвергнут ответ. Узнаём его через маршрут до клиента (для нескольких интерфейсов это важно).
fn data_socket(local_ip: IpAddr, client: SocketAddr) -> std::io::Result<UdpSocket> {
    if local_ip.is_unspecified() {
        let routed = UdpSocket::bind((local_ip, 0))
            .and_then(|probe| {
                probe.connect(client)?;
                probe.local_addr()
            })
            .map(|a| a.ip());
        if let Ok(ip) = routed {
            if !ip.is_unspecified() {
                if let Ok(s) = UdpSocket::bind((ip, 0)) {
                    return Ok(s);
                }
            }
        }
    }
    UdpSocket::bind((local_ip, 0))
}

/// Предпочитаем IPv4 (иначе, например, `localhost` → `::1` ломал бы IPv4-сокет).
fn resolve(server: &str, port: u16) -> Result<SocketAddr, TftpError> {
    let addrs: Vec<SocketAddr> = (server.trim(), port)
        .to_socket_addrs()
        .map_err(TftpError::Io)?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| TftpError::Protocol("не удалось разрешить адрес".into()))
}

/// Сокет с тем же семейством адресов, что и у собеседника.
fn bind_for(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    if addr.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0")
    } else {
        UdpSocket::bind("[::]:0")
    }
}

/// Читает до заполнения буфера или конца файла (обычный `read` может вернуть меньше).
fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Общий хэш (hex) на данный момент; сам хэшер при этом не расходуется.
fn hex(h: &blake3::Hasher) -> String {
    h.finalize().to_hex().to_string()
}

/// Добавляет файл в общий хэш: имя, 0, содержимое, размер (8 байт). Возвращает размер.
/// Отправитель считает так заранее, получатель — на лету, пока файл пишется на диск.
fn feed_reader<R: Read + ?Sized>(
    h: &mut blake3::Hasher,
    buf: &mut [u8],
    name: &str,
    r: &mut R,
    cancel: &AtomicBool,
) -> std::io::Result<u64> {
    h.update(name.as_bytes());
    h.update(&[0u8]);
    let mut size = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(ErrorKind::Other, "cancelled"));
        }
        let n = match r.read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        size += n as u64;
    }
    h.update(&size.to_be_bytes());
    Ok(size)
}

fn short(hex: &str) -> &str {
    hex.get(..8).unwrap_or(hex)
}

/// Состояние проверки на стороне получателя: ожидаемый общий хэш, список файлов и
/// хэш, который накапливается по мере приёма (файлы приходят в том же порядке, что в списке).
struct Session {
    expected: String,
    files: Vec<(String, u64)>,
    next: usize,
    hasher: blake3::Hasher,
    errors: Vec<String>,
    verdict: Option<Result<(), String>>,
}

impl Session {
    /// Вызывается перед приёмом файла. Ok — файл идёт по списку, и его содержимое надо скармливать
    /// `self.hasher` (имя уже учтено). Err — файла нет на этом месте списка; в хэш он не попадёт.
    fn start_file(&mut self, name: &str) -> Result<(), String> {
        match self.files.get(self.next) {
            Some((want, _)) if want == name => {
                self.hasher.update(name.as_bytes());
                self.hasher.update(&[0u8]);
                Ok(())
            }
            Some((want, _)) => {
                let m = format!("{name}: получен не в том порядке (ожидался {want})");
                self.errors.push(m.clone());
                Err(m)
            }
            None => {
                let m = format!("{name}: этого файла нет в списке отправителя");
                self.errors.push(m.clone());
                Err(m)
            }
        }
    }

    /// Вызывается после успешного приёма. `fed` — это значение, с которым файл прошёл `start_file`;
    /// `size` — сколько байт записано. Когда принят последний файл списка, выносится вердикт.
    fn finish_file(&mut self, name: &str, fed: bool, size: u64) -> Option<String> {
        let mut problem = None;
        if fed {
            self.hasher.update(&size.to_be_bytes());
            let want = self.files[self.next].1;
            self.next += 1;
            if size != want {
                problem = Some(format!("{name}: размер не совпал ({size} байт вместо {want})"));
            }
        }
        if let Some(p) = &problem {
            self.errors.push(p.clone());
        }
        if self.next == self.files.len() && self.verdict.is_none() {
            let got = hex(&self.hasher);
            self.verdict = Some(if !self.errors.is_empty() {
                Err(self.errors.join("; "))
            } else if got != self.expected {
                Err(format!(
                    "контрольная сумма всей передачи не совпала (ожидалась {}…, получена {}…)",
                    short(&self.expected),
                    short(&got)
                ))
            } else {
                Ok(())
            });
        }
        problem
    }

    /// Передача файла оборвалась: хэш уже неполный, проверка не может пройти.
    fn abort_file(&mut self, name: &str, why: &str) {
        self.errors.push(format!("{name}: приём прерван ({why})"));
    }
}

/// Пишет в файл и одновременно кормит данные общему хэшу — отдельный проход по файлу не нужен.
struct HashingWriter<'a> {
    inner: File,
    hasher: Option<&'a mut blake3::Hasher>,
    size: u64,
}

impl Write for HashingWriter<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.inner.write_all(b)?;
        if let Some(h) = self.hasher.as_mut() {
            h.update(b);
        }
        self.size += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Разбор списка: первая строка — общий хэш (hex), дальше по строке `размер имя` на файл.
fn parse_manifest(data: &[u8]) -> Option<Session> {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.lines();
    let expected = lines.next()?.trim().to_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut files = Vec::new();
    for line in lines {
        let (size, name) = line.split_once(' ')?;
        files.push((name.to_string(), size.parse::<u64>().ok()?));
    }
    if files.is_empty() {
        return None;
    }
    Some(Session {
        expected,
        files,
        next: 0,
        hasher: blake3::Hasher::new(),
        errors: Vec::new(),
        verdict: None,
    })
}

/// Буфер в памяти с ограничением размера (список приходит от сети).
struct LimitedBuf {
    data: Vec<u8>,
    max: usize,
}

impl Write for LimitedBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.data.len() + b.len() > self.max {
            return Err(std::io::Error::new(ErrorKind::Other, "список хэшей слишком большой"));
        }
        self.data.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ============================= NETASCII =============================

/// Перевод строки хоста: на Windows это CR LF, на остальных системах LF.
const NATIVE_CRLF: bool = cfg!(windows);

/// Текст хоста → netascii. Читается как обычный `Read`, размер данных на проводе может быть
/// больше (LF → CR LF, CR → CR NUL). Байты ≥ 0x80 идут как есть.
struct NetasciiEncoder<'a> {
    inner: &'a mut dyn Read,
    queue: Vec<u8>,
    pos: usize,
    held_cr: bool, // видели CR и ждём, что за ним (нужно только при CR LF как переводе строки хоста)
    native_crlf: bool,
    eof: bool,
}

impl<'a> NetasciiEncoder<'a> {
    fn new(inner: &'a mut dyn Read) -> Self {
        Self::with_newline(inner, NATIVE_CRLF)
    }

    fn with_newline(inner: &'a mut dyn Read, native_crlf: bool) -> Self {
        NetasciiEncoder { inner, queue: Vec::new(), pos: 0, held_cr: false, native_crlf, eof: false }
    }

    fn push(&mut self, b: u8) {
        if self.held_cr {
            self.held_cr = false;
            if b == b'\n' {
                self.queue.extend_from_slice(b"\r\n"); // CR LF хоста → CR LF
                return;
            }
            self.queue.extend_from_slice(b"\r\0"); // одиночный CR → CR NUL
        }
        match b {
            b'\r' if self.native_crlf => self.held_cr = true,
            b'\r' => self.queue.extend_from_slice(b"\r\0"),
            b'\n' => self.queue.extend_from_slice(b"\r\n"),
            _ => self.queue.push(b),
        }
    }
}

impl Read for NetasciiEncoder<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.queue.len() {
            if self.eof {
                return Ok(0);
            }
            self.queue.clear();
            self.pos = 0;
            let mut chunk = [0u8; BLOCK_SIZE];
            let n = match self.inner.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                self.eof = true;
                if self.held_cr {
                    self.held_cr = false;
                    self.queue.extend_from_slice(b"\r\0");
                }
                continue;
            }
            for &b in &chunk[..n] {
                self.push(b);
            }
        }
        let n = buf.len().min(self.queue.len() - self.pos);
        buf[..n].copy_from_slice(&self.queue[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// netascii → текст хоста. CR может прийти в конце одного блока, а его пара (LF или NUL) —
/// в начале следующего, поэтому состояние хранится между вызовами. В конце обязательно `finish()`.
struct NetasciiDecoder<'a> {
    inner: &'a mut dyn Write,
    pending_cr: bool,
    native_crlf: bool,
}

impl<'a> NetasciiDecoder<'a> {
    fn new(inner: &'a mut dyn Write) -> Self {
        Self::with_newline(inner, NATIVE_CRLF)
    }

    fn with_newline(inner: &'a mut dyn Write, native_crlf: bool) -> Self {
        NetasciiDecoder { inner, pending_cr: false, native_crlf }
    }

    fn feed(&mut self, b: u8, out: &mut Vec<u8>) {
        if self.pending_cr {
            self.pending_cr = false;
            match b {
                b'\n' => {
                    if self.native_crlf {
                        out.extend_from_slice(b"\r\n");
                    } else {
                        out.push(b'\n');
                    }
                    return;
                }
                0 => {
                    out.push(b'\r'); // CR NUL → CR
                    return;
                }
                _ => out.push(b'\r'), // CR без пары (нарушение RFC): сохраняем как есть
            }
        }
        if b == b'\r' {
            self.pending_cr = true;
        } else {
            out.push(b);
        }
    }

    /// Дописывает CR, оставшийся в конце потока, и сбрасывает буфер.
    fn finish(&mut self) -> std::io::Result<()> {
        if self.pending_cr {
            self.pending_cr = false;
            self.inner.write_all(b"\r")?;
        }
        self.inner.flush()
    }
}

impl Write for NetasciiDecoder<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut out = Vec::with_capacity(data.len() + 1);
        for &b in data {
            self.feed(b, &mut out);
        }
        self.inner.write_all(&out)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// `file.ext` → `file.ext.part` (пишем во временный файл, затем переименовываем).
fn part_path(p: &Path) -> PathBuf {
    let mut s: OsString = p.as_os_str().to_owned();
    s.push(".part");
    PathBuf::from(s)
}

/// Ждёт пакет до `deadline`. Пакеты от чужого адреса (если `expect` задан)
/// отвергаются ошибкой 5 (unknown TID) и не сбивают ожидание.
/// `Ok(None)` — время вышло.
fn recv_packet(
    sock: &UdpSocket,
    buf: &mut [u8],
    expect: Option<SocketAddr>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Option<(usize, SocketAddr)>, TftpError> {
    loop {
        // ждём короткими отрезками, чтобы остановка срабатывала сразу, а не после таймаута
        if cancel.load(Ordering::Relaxed) {
            return Err(TftpError::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        sock.set_read_timeout(Some((deadline - now).min(CANCEL_POLL).max(Duration::from_millis(1))))?;
        match sock.recv_from(buf) {
            Ok((len, from)) => {
                if let Some(p) = expect {
                    if from != p {
                        let _ = sock.send_to(&build_error(5, "Unknown transfer ID"), from);
                        continue;
                    }
                }
                return Ok(Some((len, from)));
            }
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => continue, // срок проверяется в начале цикла
                ErrorKind::Interrupted | ErrorKind::ConnectionReset => continue,
                _ => return Err(e.into()),
            },
        }
    }
}

/// Пакет с неожиданным кодом операции от собеседника, чей TID уже известен: по RFC отвечаем
/// ошибкой (4 — недопустимая операция, 8 — OACK, которого мы не просили) и прекращаем передачу.
fn reject_opcode(sock: &UdpSocket, peer: SocketAddr, op: u16) -> TftpError {
    let (code, msg) = if op == OP_OACK {
        (8, "Options were not requested")
    } else {
        (4, "Illegal TFTP operation")
    };
    let _ = sock.send_to(&build_error(code, msg), peer);
    TftpError::Protocol(format!("получен пакет с недопустимым кодом операции {op}"))
}

/// Освобождает место в счётчике фоновых «задержек» при любом выходе из потока.
struct DallySlot;
impl Drop for DallySlot {
    fn drop(&mut self) {
        DALLYING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// После последнего ACK ждёт `DALLY` и отвечает тем же ACK, если отправитель повторил последний
/// DATA (значит, наш ACK потерялся). Работает в фоне на копии сокета; если потоков уже много,
/// просто ничего не делает (передача от этого не портится).
fn dally(sock: &UdpSocket, peer: SocketAddr, block: u16) {
    if DALLYING.fetch_add(1, Ordering::SeqCst) >= MAX_DALLY_THREADS {
        DALLYING.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let slot = DallySlot;
    let Ok(s) = sock.try_clone() else { return };
    let ack = build_ack(block);
    let _ = std::thread::Builder::new().stack_size(128 * 1024).spawn(move || {
        let _slot = slot;
        let deadline = Instant::now() + DALLY;
        let mut buf = [0u8; RECV_BUF];
        while let Ok(Some((len, _))) = recv_packet(&s, &mut buf, Some(peer), deadline, &NEVER) {
            if len >= 4 && opcode_of(&buf) == OP_DATA && u16::from_be_bytes([buf[2], buf[3]]) == block {
                let _ = s.send_to(&ack, peer);
            }
        }
    });
}

/// Отправка файла блоками по 512 байт с ожиданием ACK.
/// Дубликаты ACK игнорируются (иначе возникает «Sorcerer's Apprentice»).
fn send_blocks(
    sock: &UdpSocket,
    peer: SocketAddr,
    file: &mut dyn Read,
    total: Option<u64>,
    cancel: &AtomicBool,
    log: &mut dyn FnMut(&str),
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<u64, TftpError> {
    let mut block: u16 = 1;
    let mut sent: u64 = 0;
    let mut data = [0u8; BLOCK_SIZE];
    let mut rbuf = [0u8; RECV_BUF];
    progress(0, total);

    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = sock.send_to(&build_error(0, CANCEL_MSG), peer);
            return Err(TftpError::Cancelled);
        }
        let n = match read_full(file, &mut data) {
            Ok(n) => n,
            Err(e) => {
                let _ = sock.send_to(&build_error(0, "File read error"), peer);
                return Err(e.into());
            }
        };
        let packet = build_data(block, &data[..n]);
        let mut retries = 0u32;

        'wait: loop {
            sock.send_to(&packet, peer)?;
            let deadline = Instant::now() + TIMEOUT;
            loop {
                let got = recv_packet(sock, &mut rbuf, Some(peer), deadline, cancel);
                if matches!(got, Err(TftpError::Cancelled)) {
                    let _ = sock.send_to(&build_error(0, CANCEL_MSG), peer);
                }
                let Some((len, _)) = got? else {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(TftpError::Timeout);
                    }
                    log(&format!("  таймаут, повтор блока {block} ({retries}/{MAX_RETRIES})"));
                    continue 'wait;
                };
                if len < 4 {
                    continue;
                }
                match opcode_of(&rbuf) {
                    OP_ERROR => return Err(parse_error(&rbuf[..len])),
                    OP_ACK if u16::from_be_bytes([rbuf[2], rbuf[3]]) == block => break 'wait,
                    OP_ACK => {} // дубликат ACK предыдущего блока — просто ждём дальше
                    op => return Err(reject_opcode(sock, peer, op)),
                }
            }
        }

        sent += n as u64;
        progress(sent, total);

        if n < BLOCK_SIZE {
            return Ok(sent); // последний блок короче 512 байт — конец
        }
        block = block.wrapping_add(1); // после 65535 счётчик переходит на 0
    }
}

/// Итог приёма: все данные получены, но последний ACK ещё не отправлен.
struct Received {
    total: u64,
    last_block: u16,
    peer: SocketAddr,
}

/// Отправляет последний ACK и остаётся ждать возможного повтора последнего DATA (см. `dally`).
fn ack_final(sock: &UdpSocket, r: &Received) -> Result<(), TftpError> {
    sock.send_to(&build_ack(r.last_block), r.peer)?;
    dally(sock, r.peer, r.last_block);
    Ok(())
}

/// Вместо последнего ACK сообщает отправителю об ошибке (например, файл не удалось сохранить).
fn fail_final(sock: &UdpSocket, r: &Received, code: u16, msg: &str) {
    let _ = sock.send_to(&build_error(code, msg), r.peer);
}

/// Приём файла блоками с немедленным последним ACK (для данных, которые никуда не сохраняются
/// «после»: буфер в памяти, клиентский `get_file`).
fn recv_blocks(
    sock: &UdpSocket,
    first_addr: SocketAddr,
    first_packet: Vec<u8>,
    peer: Option<SocketAddr>,
    cancel: &AtomicBool,
    out: &mut dyn Write,
    log: &mut dyn FnMut(&str),
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<u64, TftpError> {
    let r = recv_blocks_deferred(sock, first_addr, first_packet, peer, cancel, out, log, progress)?;
    ack_final(sock, &r)?;
    Ok(r.total)
}

/// Приём файла блоками. `first_packet` (RRQ или ACK 0) отправляется на `first_addr`;
/// если `peer` неизвестен — им становится отправитель первого корректного DATA.
///
/// Последний ACK НЕ отправляется: отправитель считает передачу законченной, получив его, поэтому
/// его нужно слать только когда файл уже сохранён (иначе клиент, сразу запросивший файл обратно,
/// его не найдёт). Вызывающий отправляет `ack_final` или `fail_final`.
fn recv_blocks_deferred(
    sock: &UdpSocket,
    first_addr: SocketAddr,
    first_packet: Vec<u8>,
    mut peer: Option<SocketAddr>,
    cancel: &AtomicBool,
    out: &mut dyn Write,
    log: &mut dyn FnMut(&str),
    progress: &mut dyn FnMut(u64, Option<u64>),
) -> Result<Received, TftpError> {
    let mut last = first_packet;
    let mut expected: u16 = 1;
    let mut total: u64 = 0;
    let mut retries = 0u32;
    let mut rbuf = [0u8; RECV_BUF];
    progress(0, None);

    sock.send_to(&last, peer.unwrap_or(first_addr))?;
    loop {
        let deadline = Instant::now() + TIMEOUT;
        let got = recv_packet(sock, &mut rbuf, peer, deadline, cancel);
        if matches!(got, Err(TftpError::Cancelled)) {
            if let Some(p) = peer {
                let _ = sock.send_to(&build_error(0, CANCEL_MSG), p);
            }
        }
        let Some((len, from)) = got? else {
            retries += 1;
            if retries > MAX_RETRIES {
                return Err(TftpError::Timeout);
            }
            log(&format!("  таймаут, повтор ({retries}/{MAX_RETRIES})"));
            sock.send_to(&last, peer.unwrap_or(first_addr))?; // повтор туда, куда надо
            continue;
        };
        if len < 4 {
            continue;
        }
        match opcode_of(&rbuf) {
            OP_ERROR => return Err(parse_error(&rbuf[..len])),
            OP_DATA => {
                let block = u16::from_be_bytes([rbuf[2], rbuf[3]]);
                let payload = &rbuf[4..len];
                if payload.len() > BLOCK_SIZE {
                    let _ = sock.send_to(&build_error(4, "Data block larger than 512 bytes"), from);
                    return Err(TftpError::Protocol("блок данных больше 512 байт".into()));
                }
                if peer.is_none() && block != expected {
                    continue; // TID фиксируем только по корректному первому блоку
                }
                let target = *peer.get_or_insert(from);
                if block == expected {
                    if let Err(e) = out.write_all(payload) {
                        // диск переполнен или ошибка записи — сообщаем отправителю, иначе он будет ждать зря
                        let _ = sock.send_to(&build_error(3, "Disk full or write error"), target);
                        return Err(e.into());
                    }
                    total += payload.len() as u64;
                    progress(total, None);
                    if payload.len() < BLOCK_SIZE {
                        return Ok(Received { total, last_block: block, peer: target });
                    }
                    let ack = build_ack(block);
                    sock.send_to(&ack, target)?;
                    retries = 0;
                    expected = expected.wrapping_add(1);
                    last = ack.to_vec();
                } else if block == expected.wrapping_sub(1) {
                    // дубликат — повторяем ACK предыдущего блока
                    sock.send_to(&build_ack(block), target)?;
                }
            }
            op if peer.is_some() => return Err(reject_opcode(sock, peer.unwrap(), op)),
            _ => {} // до установления TID посторонний мусор просто игнорируем
        }
    }
}

// ============================= КЛИЕНТ =============================

/// Отправить файл на TFTP-сервер (WRQ, режим octet).
pub fn put_file(
    server: &str,
    port: u16,
    remote_filename: &str,
    local_path: &Path,
    log: impl FnMut(&str),
    progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    put_file_mode(server, port, remote_filename, local_path, Mode::Octet, log, progress)
}

/// То же с выбором режима. В netascii текст хоста переводится в сетевой вид на лету;
/// размер на проводе заранее неизвестен, поэтому прогресс идёт без общего размера.
pub fn put_file_mode(
    server: &str,
    port: u16,
    remote_filename: &str,
    local_path: &Path,
    mode: Mode,
    log: impl FnMut(&str),
    progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    put_file_cancel(server, port, remote_filename, local_path, mode, &NEVER, log, progress)
}

/// То же с флагом остановки: как только он выставлен, отправка прекращается, а получателю уходит ошибка.
#[allow(clippy::too_many_arguments)]
fn put_file_cancel(
    server: &str,
    port: u16,
    remote_filename: &str,
    local_path: &Path,
    mode: Mode,
    cancel: &AtomicBool,
    log: impl FnMut(&str),
    progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    let mut file = File::open(local_path)?;
    let total = match mode {
        Mode::Octet => file.metadata().ok().map(|m| m.len()),
        Mode::Netascii => None,
    };
    put_reader(server, port, remote_filename, mode, &mut file, total, cancel, log, progress)
}

/// Отправка произвольных данных (файл или буфер в памяти) на TFTP-сервер (WRQ).
#[allow(clippy::too_many_arguments)]
fn put_reader(
    server: &str,
    port: u16,
    remote_filename: &str,
    mode: Mode,
    reader: &mut dyn Read,
    total: Option<u64>,
    cancel: &AtomicBool,
    mut log: impl FnMut(&str),
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    let addr = resolve(server, port)?;
    let sock = bind_for(addr)?;

    log(&format!("→ WRQ {remote_filename} на {}", addr.ip()));
    let wrq = build_rq(OP_WRQ, remote_filename, mode);
    let mut rbuf = [0u8; RECV_BUF];
    let mut retries = 0u32;

    // Ждём ACK 0; адрес ответившего — это TID сервера, дальше говорим только с ним.
    let peer = 'req: loop {
        sock.send_to(&wrq, addr)?;
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let Some((len, from)) = recv_packet(&sock, &mut rbuf, None, deadline, cancel)? else {
                retries += 1;
                if retries > MAX_RETRIES {
                    return Err(TftpError::Timeout);
                }
                log(&format!("  таймаут, повтор WRQ ({retries}/{MAX_RETRIES})"));
                continue 'req;
            };
            if len < 4 {
                continue;
            }
            match opcode_of(&rbuf) {
                OP_ERROR => return Err(parse_error(&rbuf[..len])),
                OP_ACK if u16::from_be_bytes([rbuf[2], rbuf[3]]) == 0 => break 'req from,
                OP_OACK => return Err(reject_opcode(&sock, from, OP_OACK)),
                _ => {}
            }
        }
    };
    log(&format!("  запрос принят, сервер отвечает с {}", peer.ip()));

    match mode {
        Mode::Octet => send_blocks(&sock, peer, reader, total, cancel, &mut log, &mut progress)?,
        Mode::Netascii => {
            let mut enc = NetasciiEncoder::new(reader);
            send_blocks(&sock, peer, &mut enc, total, cancel, &mut log, &mut progress)?
        }
    };
    log("✓ Передача завершена");
    Ok(())
}

/// Скачивает небольшой служебный ответ (RRQ) целиком в память.
fn fetch_bytes(server: &str, port: u16, name: &str, cancel: &AtomicBool) -> Result<Vec<u8>, TftpError> {
    let addr = resolve(server, port)?;
    let sock = bind_for(addr)?;
    let mut out: Vec<u8> = Vec::new();
    recv_blocks(
        &sock,
        addr,
        build_rq(OP_RRQ, name, Mode::Octet),
        None,
        cancel,
        &mut out,
        &mut |_: &str| {},
        &mut |_, _| {},
    )?;
    Ok(out)
}

/// Получить файл с TFTP-сервера (RRQ, режим octet).
/// Данные пишутся во временный `*.part`, который переименовывается только при успехе —
/// существующий файл не портится, а при ошибке не остаётся мусора.
pub fn get_file(
    server: &str,
    port: u16,
    remote_filename: &str,
    local_path: &Path,
    log: impl FnMut(&str),
    progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    get_file_mode(server, port, remote_filename, local_path, Mode::Octet, log, progress)
}

/// То же с выбором режима (в netascii принятый текст переводится в вид, принятый на этой системе).
pub fn get_file_mode(
    server: &str,
    port: u16,
    remote_filename: &str,
    local_path: &Path,
    mode: Mode,
    mut log: impl FnMut(&str),
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    let addr = resolve(server, port)?;
    let sock = bind_for(addr)?;
    let tmp = part_path(local_path);
    let mut out = File::create(&tmp)?;

    log(&format!("→ RRQ {remote_filename} с {}", addr.ip()));
    let rq = build_rq(OP_RRQ, remote_filename, mode);
    let res = match mode {
        Mode::Octet => recv_blocks(&sock, addr, rq, None, &NEVER, &mut out, &mut log, &mut progress),
        Mode::Netascii => {
            let mut dec = NetasciiDecoder::new(&mut out);
            recv_blocks(&sock, addr, rq, None, &NEVER, &mut dec, &mut log, &mut progress)
                .and_then(|n| dec.finish().map(|_| n).map_err(TftpError::from))
        }
    };
    drop(out);

    match res {
        Ok(_) => {
            std::fs::rename(&tmp, local_path).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                TftpError::Io(e)
            })?;
            log("✓ Приём завершён");
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// ============================= СЕРВЕР =============================

type SharedLog = Arc<Mutex<dyn FnMut(&str) + Send>>;

fn log_to(log: &SharedLog, msg: &str) {
    if let Ok(mut guard) = log.lock() {
        let f: &mut (dyn FnMut(&str) + Send) = &mut *guard;
        f(msg);
    }
}

/// Безопасно превращает имя из запроса в путь внутри `root` (который уже canonicalize-нут).
/// Запрещает `..`, абсолютные пути и выход через симлинки.
/// `must_exist` = true для чтения (файл должен существовать), false для записи.
fn resolve_in_root(root: &Path, filename: &str, must_exist: bool) -> Option<PathBuf> {
    if filename.is_empty() || filename.contains('\0') {
        return None;
    }
    let mut p = root.to_path_buf();
    for c in Path::new(filename).components() {
        match c {
            Component::Normal(x) => p.push(x),
            Component::CurDir => {}
            _ => return None, // ParentDir, RootDir, Prefix
        }
    }
    if p == root {
        return None;
    }
    if must_exist {
        let canon = p.canonicalize().ok()?;
        canon.starts_with(root).then_some(canon)
    } else {
        let parent = p.parent()?.canonicalize().ok()?;
        if !parent.starts_with(root) {
            return None;
        }
        let target = parent.join(p.file_name()?);
        if let Ok(md) = std::fs::symlink_metadata(&target) {
            if md.file_type().is_symlink() {
                return None;
            }
        }
        Some(target)
    }
}

/// Запускает TFTP-сервер в текущем потоке (вызывать из отдельного std::thread).
/// Каждая передача обрабатывается в своём потоке со своим сокетом (свой TID).
pub fn run_server(
    bind_addr: &str,
    port: u16,
    root_dir: PathBuf,
    stop: Arc<AtomicBool>,
    log: impl FnMut(&str) + Send + 'static,
) -> Result<(), TftpError> {
    let bind_addr = bind_addr.trim();
    let root = root_dir.canonicalize()?;
    let sock = UdpSocket::bind((bind_addr, port))?;
    sock.set_read_timeout(Some(Duration::from_millis(300)))?;
    let local_ip: IpAddr = sock.local_addr()?.ip();

    let log: SharedLog = Arc::new(Mutex::new(log));
    // Активные передачи: повторный запрос (клиент не дождался ACK) не порождает второй поток.
    let active: Arc<Mutex<HashSet<(SocketAddr, String)>>> = Arc::new(Mutex::new(HashSet::new()));

    log_to(&log, &format!("Сервер слушает {bind_addr}, каталог: {}", root.display()));

    let mut buf = [0u8; RECV_BUF];
    while !stop.load(Ordering::Relaxed) {
        let (len, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock
                | ErrorKind::TimedOut
                | ErrorKind::Interrupted
                | ErrorKind::ConnectionReset => continue,
                _ => return Err(e.into()),
            },
        };
        if len < 2 {
            continue;
        }
        let opcode = opcode_of(&buf);
        if opcode != OP_RRQ && opcode != OP_WRQ {
            continue; // в том числе наши служебные пакеты поиска: обычному серверу они ни к чему
        }
        let is_read = opcode == OP_RRQ;
        let kind = if is_read { "RRQ" } else { "WRQ" };

        let Some((filename, mode)) = parse_rq(&buf[..len]) else {
            let _ = sock.send_to(&build_error(4, "Malformed request"), from);
            continue;
        };
        let Some(mode) = accept_mode(&sock, from, &mode) else {
            log_to(&log, &format!("[{}] {kind} {filename}: режим «{mode}» не поддерживается", from.ip()));
            continue;
        };

        let fresh = active
            .lock()
            .map(|mut a| a.insert((from, filename.clone())))
            .unwrap_or(true);
        if !fresh {
            continue;
        }
        log_to(&log, &format!("[{}] {kind} {filename}", from.ip()));

        let root = root.clone();
        let log = log.clone();
        let active = active.clone();
        std::thread::spawn(move || {
            let res = if is_read {
                serve_rrq(local_ip, from, &filename, mode, &root, &log)
            } else {
                serve_wrq(local_ip, from, &filename, mode, &root, &log)
            };
            match res {
                Ok(n) => log_to(&log, &format!("[{}] {kind} {filename}: готово, {n} байт", from.ip())),
                Err(e) => log_to(&log, &format!("[{}] {kind} {filename}: {e}", from.ip())),
            }
            if let Ok(mut a) = active.lock() {
                a.remove(&(from, filename));
            }
        });
    }
    log_to(&log, "Сервер остановлен");
    Ok(())
}

fn serve_rrq(
    local_ip: IpAddr,
    client: SocketAddr,
    filename: &str,
    mode: Mode,
    root: &Path,
    log: &SharedLog,
) -> Result<u64, TftpError> {
    let sock = data_socket(local_ip, client)?;

    let path = match resolve_in_root(root, filename, true) {
        Some(p) if p.is_file() => p,
        _ => {
            let _ = sock.send_to(&build_error(1, "File not found"), client);
            return Err(TftpError::Protocol("файл не найден".into()));
        }
    };
    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            let _ = sock.send_to(&build_error(2, "Access violation"), client);
            return Err(TftpError::Protocol("нет доступа к файлу".into()));
        }
    };
    let mut on_log = |m: &str| log_to(log, &format!("[{client}] {m}"));
    match mode {
        Mode::Octet => {
            let total = file.metadata().ok().map(|m| m.len());
            send_blocks(&sock, client, &mut file, total, &NEVER, &mut on_log, &mut |_, _| {})
        }
        Mode::Netascii => {
            let mut enc = NetasciiEncoder::new(&mut file);
            send_blocks(&sock, client, &mut enc, None, &NEVER, &mut on_log, &mut |_, _| {})
        }
    }
}

fn serve_wrq(
    local_ip: IpAddr,
    client: SocketAddr,
    filename: &str,
    mode: Mode,
    root: &Path,
    log: &SharedLog,
) -> Result<u64, TftpError> {
    let sock = data_socket(local_ip, client)?;

    let Some(target) = resolve_in_root(root, filename, false) else {
        let _ = sock.send_to(&build_error(2, "Access violation"), client);
        return Err(TftpError::Protocol("недопустимое имя файла".into()));
    };
    let tmp = part_path(&target);
    let mut out = match File::create(&tmp) {
        Ok(f) => f,
        Err(_) => {
            let _ = sock.send_to(&build_error(2, "Access violation"), client);
            return Err(TftpError::Protocol("не удалось создать файл".into()));
        }
    };

    // подтверждаем WRQ пакетом ACK 0 и принимаем данные
    let mut on_log = |m: &str| log_to(log, &format!("[{client}] {m}"));
    let res = match mode {
        Mode::Octet => recv_blocks_deferred(
            &sock,
            client,
            build_ack(0).to_vec(),
            Some(client),
            &NEVER,
            &mut out,
            &mut on_log,
            &mut |_, _| {},
        ),
        Mode::Netascii => {
            let mut dec = NetasciiDecoder::new(&mut out);
            recv_blocks_deferred(
                &sock,
                client,
                build_ack(0).to_vec(),
                Some(client),
                &NEVER,
                &mut dec,
                &mut on_log,
                &mut |_, _| {},
            )
            .and_then(|r| dec.finish().map(|_| r).map_err(TftpError::from))
        }
    };
    drop(out);

    match res {
        Ok(r) => {
            // последний ACK — только после того, как файл лёг на место
            if let Err(e) = std::fs::rename(&tmp, &target) {
                let _ = std::fs::remove_file(&tmp);
                fail_final(&sock, &r, 0, "Cannot store file");
                return Err(TftpError::Io(e));
            }
            ack_final(&sock, &r)?;
            Ok(r.total)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp); // ошибку 3 при сбое записи recv_blocks уже отправил
            Err(e)
        }
    }
}

// ============================= ПРИЁМ / ОТПРАВКА ДЛЯ GUI =============================

/// Пакеты поиска устройств. Первый байт 'T' даёт «код операции» 0x54xx, которого нет в TFTP,
/// поэтому обычные TFTP-серверы такие пакеты просто игнорируют.
const DISCOVER_MAGIC: &[u8] = b"TFTP-DISCOVER";
const HERE_MAGIC: &[u8] = b"TFTP-HERE";

/// IPv4-адреса всех сетевых интерфейсов, кроме loopback: (имя интерфейса, адрес).
/// Не зависит от маршрута в интернет, поэтому работает и при прямом кабеле между двумя компьютерами.
pub fn local_ips() -> Vec<(String, IpAddr)> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| (i.name.clone(), i.ip()))
        .filter(|(_, ip)| ip.is_ipv4())
        .collect()
}

fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Ищет в локальной сети устройства, которые сейчас ждут файл (нажато «Начать приём»).
/// Рассылает запрос на широковещательные адреса всех интерфейсов и собирает ответы `wait`.
/// Возвращает (адрес, имя компьютера).
pub fn discover(port: u16, wait: Duration) -> Vec<(IpAddr, String)> {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.send_to(DISCOVER_MAGIC, (Ipv4Addr::LOCALHOST, port)); // приём на этом же компьютере
    let _ = sock.send_to(DISCOVER_MAGIC, (Ipv4Addr::BROADCAST, port));
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if iface.is_loopback() {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = &iface.addr {
            if let Some(b) = v4.broadcast {
                let _ = sock.send_to(DISCOVER_MAGIC, (b, port));
            }
        }
    }

    let mut found: Vec<(IpAddr, String)> = Vec::new();
    let deadline = Instant::now() + wait;
    let mut buf = [0u8; 256];
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let _ = sock.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))));
        match sock.recv_from(&mut buf) {
            Ok((len, from)) => {
                if buf[..len].starts_with(HERE_MAGIC) && !found.iter().any(|(ip, _)| *ip == from.ip()) {
                    let name = String::from_utf8_lossy(&buf[HERE_MAGIC.len()..len]).trim().to_string();
                    found.push((from.ip(), name));
                }
            }
            Err(e) => match e.kind() {
                ErrorKind::Interrupted | ErrorKind::ConnectionReset => continue,
                _ => break,
            },
        }
    }
    found.sort_by_key(|(ip, _)| ip.to_string());
    found
}

/// Если файл уже есть, подбирает `name (1).ext`, `name (2).ext`, … — принятое ничего не затирает.
fn unique_path(p: PathBuf) -> PathBuf {
    if std::fs::symlink_metadata(&p).is_err() {
        return p;
    }
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
    for i in 1..10_000 {
        let cand = dir.join(format!("{stem} ({i}){ext}"));
        if std::fs::symlink_metadata(&cand).is_err() {
            return cand;
        }
    }
    p
}

/// Готовит путь для входящего файла внутри `root`. Имя может содержать подпапки (`папка/файл.txt`) —
/// они создаются. Защита, т.к. TFTP без пароля: запрещены `..`, абсолютные пути, проход через симлинки;
/// существующие файлы не перезаписываются. Скрытые файлы и папки принимаются только внутри папки
/// (`проект/.git/config`), но не прямо в папке приёма (`~/.bashrc`, `~/.ssh` создать нельзя).
fn prepare_incoming(root: &Path, filename: &str, created_dirs: &mut Vec<PathBuf>) -> Option<PathBuf> {
    let name = filename.replace('\\', "/");
    let mut parts: Vec<&str> = name.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
    if parts.is_empty() || parts.len() > 32 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        if *p == ".." || p.contains('\0') || p.contains(':') {
            return None;
        }
        if i == 0 && p.starts_with('.') {
            return None;
        }
    }
    let file = parts.pop()?;
    let mut dir = root.to_path_buf();
    for p in parts {
        dir.push(p);
        match std::fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => return None, // файл или симлинк на месте папки
            Err(_) => {
                std::fs::create_dir(&dir).ok()?;
                created_dirs.push(dir.clone()); // при остановке приёма такие папки уберём
            }
        }
    }
    Some(unique_path(dir.join(file)))
}

/// Ошибка ввода-вывода с путём в тексте (иначе «Permission denied» непонятно к чему относится).
fn io_with_path(e: std::io::Error, p: &Path) -> TftpError {
    TftpError::Io(std::io::Error::new(e.kind(), format!("{}: {e}", p.display())))
}

/// Все обычные файлы папки (рекурсивно) с именем для отправки `папка/подпапка/файл`.
/// Скрытые файлы и папки включаются; симлинки пропускаются (они могут вести за пределы папки).
/// Недоступные для чтения подпапки не прерывают сбор: их пути попадают в `skipped`.
fn collect_files(root: &Path, skipped: &mut Vec<String>) -> Result<Vec<(PathBuf, String)>, TftpError> {
    let base = root
        .file_name()
        .map(|s| s.to_string_lossy().trim_start_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "folder".to_string());
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), base)];
    while let Some((dir, rel)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if dir != root => {
                skipped.push(format!("{} ({e})", dir.display()));
                continue;
            }
            Err(e) => return Err(io_with_path(e, &dir)),
        };
        for entry in rd {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(ft) = entry.file_type() else {
                skipped.push(entry.path().display().to_string());
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let rel_name = format!("{rel}/{name}");
            if ft.is_dir() {
                stack.push((entry.path(), rel_name));
            } else if ft.is_file() {
                out.push((entry.path(), rel_name));
            }
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

/// Отвечает ли по этому адресу наша программа (в режиме «Начать приём»), а не обычный TFTP-сервер.
/// Спрашиваем тем же пакетом поиска устройств; обычные серверы на него не отвечают HERE.
/// Расширения (контрольная сумма) включаются только при положительном ответе, иначе на обычный
/// сервер ушли бы служебные запросы, которых он не понимает.
fn peer_has_extension(server: &str, port: u16) -> bool {
    let Ok(addr) = resolve(server, port) else { return false };
    let Ok(sock) = bind_for(addr) else { return false };
    let mut buf = [0u8; 256];
    for _ in 0..PROBE_TRIES {
        if sock.send_to(DISCOVER_MAGIC, addr).is_err() {
            return false;
        }
        let deadline = Instant::now() + PROBE_WAIT;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let _ = sock.set_read_timeout(Some((deadline - now).max(Duration::from_millis(1))));
            match sock.recv_from(&mut buf) {
                Ok((len, _)) if buf[..len].starts_with(HERE_MAGIC) => return true,
                Ok(_) => return false, // ответил кто-то другой (например, ERROR) — это не наш получатель
                Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::ConnectionReset) => continue,
                Err(_) => break, // таймаут — следующая попытка
            }
        }
    }
    false
}

/// Отправить файл или папку целиком (включая скрытые файлы). Папка уходит как набор файлов
/// с относительными путями.
///
/// Если получатель — наша программа, включается проверка целостности:
/// 1) считаем ОДИН общий BLAKE3-хэш всего, что будет отправлено (имена, содержимое, размеры);
/// 2) отправляем получателю этот хэш и список файлов; 3) отправляем сами файлы; 4) спрашиваем итог:
/// получатель считает такой же общий хэш по принятому и сверяет. Расхождение — ошибка.
///
/// Если получатель — обычный TFTP-сервер (RFC 1350), файлы уходят обычными WRQ без служебных
/// запросов; проверить целостность в этом случае нечем, о чём пишется в журнал.
pub fn send_path(
    server: &str,
    port: u16,
    path: &Path,
    log: impl FnMut(&str),
    progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    send_paths(server, port, &[path.to_path_buf()], log, progress)
}

/// То же для нескольких файлов и папок сразу: всё уходит одной сессией с общей контрольной суммой.
/// Отдельные файлы кладутся в корень приёмника, папки — со своей структурой. Если два выбранных
/// файла получили бы одинаковое имя, отправка отклоняется (иначе один затёр бы другой).
pub fn send_paths(
    server: &str,
    port: u16,
    paths: &[PathBuf],
    log: impl FnMut(&str),
    progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    send_paths_cancel(server, port, paths, &NEVER, log, progress)
}

/// То же, но отправку можно остановить: как только `cancel` выставлен, файлы перестают уходить,
/// получатель узнаёт об этом ошибкой, а функция возвращает `TftpError::Cancelled`.
pub fn send_paths_cancel(
    server: &str,
    port: u16,
    paths: &[PathBuf],
    cancel: &AtomicBool,
    mut log: impl FnMut(&str),
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    let mut skipped: Vec<String> = Vec::new();
    // (путь на диске, имя у получателя, выбран ли файл явно: такой прочитать обязаны)
    let mut files: Vec<(PathBuf, String, bool)> = Vec::new();
    for path in paths {
        if path.is_file() {
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file.bin".to_string());
            files.push((path.clone(), name, true));
        } else if path.is_dir() {
            for (p, n) in collect_files(path, &mut skipped)? {
                files.push((p, n, false));
            }
        } else {
            return Err(TftpError::Protocol(format!("путь не существует: {}", path.display())));
        }
    }
    if files.is_empty() && skipped.is_empty() {
        return Err(TftpError::Protocol("в выбранном нет файлов для отправки".into()));
    }
    let mut seen = std::collections::HashSet::new();
    for (_, name, _) in &files {
        if !seen.insert(name.as_str()) {
            return Err(TftpError::Protocol(format!(
                "два выбранных файла получили бы одно имя «{name}» — отправьте их по отдельности"
            )));
        }
    }

    // 0. кто на той стороне: наша программа (с проверкой) или обычный TFTP-сервер
    progress(0, None);
    let verify = peer_has_extension(server, port);
    if cancel.load(Ordering::Relaxed) {
        return Err(TftpError::Cancelled);
    }
    if !verify {
        log("Получатель не подтвердил расширения (обычный TFTP-сервер или наш приём занят другой передачей): \
             передача по RFC 1350, контрольная сумма не проверяется");
    }

    // 1. общая контрольная сумма всего, что будет отправлено (до отправки данных)
    if verify {
        log(&format!("Считаю общую контрольную сумму (файлов: {})…", files.len()));
    }
    let mut hasher = blake3::Hasher::new();
    let mut hash_buf = vec![0u8; 1 << 20];
    let mut list = String::new();
    let mut ready: Vec<(PathBuf, String)> = Vec::with_capacity(files.len());
    let mut sizes: Vec<u64> = Vec::with_capacity(files.len());
    for (file, name, explicit) in files {
        if cancel.load(Ordering::Relaxed) {
            return Err(TftpError::Cancelled);
        }
        if verify && (name.contains('\n') || name.contains('\r')) {
            return Err(TftpError::Protocol(format!("в имени файла перевод строки: {name:?}")));
        }
        // отдельно выбранный файл прочитать обязаны; в папке недоступные файлы пропускаем
        let mut f = match File::open(&file) {
            Ok(f) => f,
            Err(e) if !explicit && e.kind() == ErrorKind::PermissionDenied => {
                skipped.push(file.display().to_string());
                continue;
            }
            Err(e) => return Err(io_with_path(e, &file)),
        };
        let size = if verify {
            feed_reader(&mut hasher, &mut hash_buf, &name, &mut f, cancel).map_err(|e| {
                if cancel.load(Ordering::Relaxed) {
                    TftpError::Cancelled
                } else {
                    io_with_path(e, &file)
                }
            })?
        } else {
            f.metadata().map_err(|e| io_with_path(e, &file))?.len()
        };
        if verify {
            list.push_str(&format!("{size} {name}\n"));
        }
        sizes.push(size);
        ready.push((file, name));
    }
    for p in &skipped {
        log(&format!("Пропущено (нет доступа): {p}"));
    }
    if ready.is_empty() {
        return Err(TftpError::Protocol("нет файлов, доступных для чтения".into()));
    }
    let files = ready;
    let count = files.len();
    let total: u64 = sizes.iter().sum();

    // 2. контрольная сумма и список файлов — получателю
    if verify {
        let total_hash = hex(&hasher);
        log(&format!("Общая контрольная сумма: {}…", total_hash.get(..16).unwrap_or(&total_hash)));
        let manifest = format!("{total_hash}\n{list}");
        log("→ отправляю контрольную сумму получателю");
        let bytes = manifest.into_bytes();
        let len = bytes.len() as u64;
        put_reader(
            server,
            port,
            MANIFEST_NAME,
            Mode::Octet,
            &mut Cursor::new(bytes),
            Some(len),
            cancel,
            |_: &str| {},
            |_, _| {},
        )?;
    }

    // 3. сами файлы
    let mut done_before = 0u64;
    for (idx, (file, name)) in files.iter().enumerate() {
        if count > 1 {
            log(&format!("[{}/{}] {name}", idx + 1, count));
        }
        let base = done_before;
        put_file_cancel(server, port, name, file, Mode::Octet, cancel, &mut log, |sent, _| {
            progress(base + sent, Some(total))
        })?;
        done_before += sizes[idx];
    }

    let skipped_note = if skipped.is_empty() {
        String::new()
    } else {
        format!(" (пропущено без доступа: {})", skipped.len())
    };
    if !verify {
        log(&format!("✓ Отправлено файлов: {count}{skipped_note}; целостность не проверялась"));
        return Ok(());
    }

    // 4. результат проверки у получателя
    log("→ жду от получателя результат проверки…");
    let body = fetch_bytes(server, port, RESULT_NAME, cancel).map_err(|e| match e {
        TftpError::Cancelled => TftpError::Cancelled,
        e => TftpError::Protocol(format!("не удалось получить от получателя результат проверки: {e}")),
    })?;
    let text = String::from_utf8_lossy(&body).into_owned();
    let mut lines = text.lines();
    match lines.next() {
        Some("OK") => {}
        Some("FAIL") => {
            let bad: Vec<&str> = lines.collect();
            return Err(TftpError::Protocol(format!(
                "проверка у получателя не пройдена: {}",
                bad.join(", ")
            )));
        }
        _ => return Err(TftpError::Protocol("непонятный ответ получателя о проверке".into())),
    }
    log(&format!("✓ Контрольная сумма совпала, отправлено файлов: {count}{skipped_note}"));
    Ok(())
}

/// «Получить»: слушает порт и принимает входящие файлы (по одному за раз), пока не выставлен `stop`.
/// Отвечает на поиск устройств. Чтение файлов (RRQ) запрещено — принимать можно только запись.
/// Если отправитель — tftp-rs и всё, что он перечислил, принято, проверено и результат ему выдан,
/// приём завершается сам (`Ok`) — так же, как по `stop`. Передачи от обычных клиентов конца не имеют:
/// там приём идёт, пока не выставлен `stop`.
/// Ошибка одного файла не останавливает приём; фатальны только ошибки запуска (порт занят и т.п.).
///
/// Остановка (`stop`) действует сразу, в том числе посреди передачи: текущий файл отбрасывается,
/// отправителю уходит ошибка, а всё, что было принято с момента запуска (файлы и созданные для них
/// папки), удаляется.
pub fn receive_loop(
    bind_addr: &str,
    port: u16,
    dir: &Path,
    stop: &AtomicBool,
    mut log: impl FnMut(&str),
    mut progress: impl FnMut(u64, Option<u64>),
) -> Result<(), TftpError> {
    let root = dir.canonicalize()?;
    let sock = UdpSocket::bind((bind_addr.trim(), port))?;
    sock.set_read_timeout(Some(Duration::from_millis(300)))?;
    let local_ip = sock.local_addr()?.ip();

    let mut hello = HERE_MAGIC.to_vec();
    hello.extend_from_slice(host_name().as_bytes());
    log(&format!("Приём запущен, папка: {}", root.display()));

    let mut buf = [0u8; RECV_BUF];
    // Отправитель мог повторить WRQ, если потерялся ACK 0: такой дубликат не должен создавать вторую копию.
    let mut last_done: Option<(SocketAddr, String, Instant)> = None;
    // Проверка целостности: общая контрольная сумма и список файлов от отправителя.
    // Сессия принадлежит одному отправителю (по IP: у каждой передачи свой порт) и живёт до выдачи
    // результата проверки. Файлы других клиентов и «лишние» файлы после завершения списка идут
    // как обычные передачи, не задевая сессию.
    let mut session: Option<Session> = None;
    let mut session_ip: Option<IpAddr> = None;
    let mut last_result: Option<(SocketAddr, Instant)> = None;
    // Что уже принято в этом запуске (для удаления при остановке).
    let mut received_files: Vec<PathBuf> = Vec::new();
    let mut created_dirs: Vec<PathBuf> = Vec::new();

    while !stop.load(Ordering::Relaxed) {
        let (len, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock
                | ErrorKind::TimedOut
                | ErrorKind::Interrupted
                | ErrorKind::ConnectionReset => continue,
                _ => return Err(e.into()),
            },
        };
        if buf[..len].starts_with(DISCOVER_MAGIC) {
            let _ = sock.send_to(&hello, from);
            continue;
        }
        if len < 2 {
            continue;
        }
        match opcode_of(&buf) {
            OP_WRQ => {}
            OP_RRQ => {
                let name = parse_rq(&buf[..len]).map(|(n, _)| n);
                if name.as_deref() == Some(RESULT_NAME) {
                    // дубликат запроса (потерялся первый пакет) не обслуживаем повторно
                    if let Some((a, t)) = &last_result {
                        if *a == from && t.elapsed() < Duration::from_secs(10) {
                            continue;
                        }
                    }
                    let own_session = session.as_ref().filter(|_| session_ip == Some(from.ip()));
                    let verdict_ok = matches!(own_session.and_then(|s| s.verdict.as_ref()), Some(Ok(())));
                    let body = match own_session {
                        None => "FAIL\nсписок файлов и контрольная сумма не были получены\n".to_string(),
                        Some(s) => match &s.verdict {
                            Some(Ok(())) => format!("OK\n{}\n", s.files.len()),
                            Some(Err(m)) => format!("FAIL\n{m}\n"),
                            None => {
                                let mut m = s.errors.join("; ");
                                if !m.is_empty() {
                                    m.push_str("; ");
                                }
                                format!("FAIL\n{m}получены не все файлы ({} из {})\n", s.next, s.files.len())
                            }
                        },
                    };
                    let bytes = body.into_bytes();
                    let total = bytes.len() as u64;
                    let mut result_delivered = false;
                    match data_socket(local_ip, from) {
                        Ok(dsock) => {
                            let r = send_blocks(
                                &dsock,
                                from,
                                &mut Cursor::new(bytes),
                                Some(total),
                                stop,
                                &mut log,
                                &mut |_, _| {},
                            );
                            match r {
                                Ok(_) => result_delivered = true,
                                Err(TftpError::Cancelled) => {}
                                Err(e) => log(&format!("Ошибка: не удалось отправить результат проверки: {e}")),
                            }
                        }
                        Err(e) => log(&format!("Ошибка: не удалось открыть сокет передачи: {e}")),
                    }
                    last_result = Some((from, Instant::now()));
                    if session_ip == Some(from.ip()) {
                        session = None; // результат выдан — сессия закрыта
                        session_ip = None;
                    }
                    if verdict_ok && result_delivered {
                        // всё, что перечислил отправитель, принято, проверено, и он об этом знает
                        log("✓ Всё принято и проверено, приём завершён");
                        return Ok(());
                    }
                } else {
                    let _ = sock.send_to(&build_error(2, "Read is not allowed"), from);
                    log(&format!(
                        "← RRQ {} от {}: чтение запрещено (Read is not allowed)",
                        name.as_deref().unwrap_or("?"),
                        from.ip()
                    ));
                }
                continue;
            }
            _ => continue,
        }
        let Some((filename, mode)) = parse_rq(&buf[..len]) else {
            let _ = sock.send_to(&build_error(4, "Malformed request"), from);
            continue;
        };
        let Some(mode) = accept_mode(&sock, from, &mode) else {
            log(&format!("← {filename} от {}: режим «{mode}» не поддерживается", from.ip()));
            continue;
        };
        if let Some((a, n, t)) = &last_done {
            if *a == from && *n == filename && t.elapsed() < Duration::from_secs(10) {
                continue;
            }
        }
        if filename == MANIFEST_NAME {
            if mode != Mode::Octet {
                let _ = sock.send_to(&build_error(4, "Manifest must be sent in octet mode"), from);
                continue;
            }
            let dsock = match data_socket(local_ip, from) {
                Ok(s) => s,
                Err(e) => {
                    log(&format!("Ошибка: не удалось открыть сокет передачи: {e}"));
                    continue;
                }
            };
            let mut list = LimitedBuf { data: Vec::new(), max: MANIFEST_MAX };
            let res = recv_blocks(
                &dsock,
                from,
                build_ack(0).to_vec(),
                Some(from),
                stop,
                &mut list,
                &mut log,
                &mut |_, _| {},
            );
            match res {
                Ok(_) => {
                    match parse_manifest(&list.data) {
                        Some(sess) => {
                            log(&format!(
                                "← получена общая контрольная сумма ({}…), файлов: {}",
                                short(&sess.expected),
                                sess.files.len()
                            ));
                            session = Some(sess);
                            session_ip = Some(from.ip());
                        }
                        None => log("Ошибка: список от отправителя повреждён, проверка невозможна"),
                    }
                    last_done = Some((from, filename, Instant::now()));
                }
                Err(TftpError::Cancelled) => {} // приём остановлен: цикл закончится сам
                Err(e) => log(&format!("Ошибка приёма контрольной суммы: {e}")),
            }
            continue;
        }
        let Some(target) = prepare_incoming(&root, &filename, &mut created_dirs) else {
            let _ = sock.send_to(&build_error(2, "Access violation"), from);
            log(&format!("← {filename} от {}: недопустимое имя, отклонено", from.ip()));
            continue;
        };

        let mode_note = if mode == Mode::Netascii { " (netascii)" } else { "" };
        log(&format!("← {filename} от {}{mode_note}", from.ip()));
        let dsock = match data_socket(local_ip, from) {
            Ok(s) => s,
            Err(e) => {
                log(&format!("Ошибка: не удалось открыть сокет передачи: {e}"));
                continue;
            }
        };
        let tmp = part_path(&target);
        let out = match File::create(&tmp) {
            Ok(f) => f,
            Err(e) => {
                let _ = dsock.send_to(&build_error(2, "Access violation"), from);
                log(&format!("Ошибка: не удалось создать {}: {e}", target.display()));
                continue;
            }
        };

        // Общий хэш считается на лету, пока файл пишется на диск. Только для octet: список от нашего
        // отправителя всегда в octet, а файл от обычного клиента в netascii в список не входит.
        let in_session = mode == Mode::Octet
            && session_ip == Some(from.ip())
            && session.as_ref().is_some_and(|s| s.verdict.is_none());
        let (fed, start_problem) = match session.as_mut() {
            Some(sess) if in_session => match sess.start_file(&filename) {
                Ok(()) => (true, None),
                Err(m) => (false, Some(m)),
            },
            _ => (false, None),
        };
        // Прогресс: если файл идёт по списку отправителя, полный размер известен заранее (сумма размеров
        // из списка), а уже принятые файлы дают начало отсчёта. У обычного клиента размер неизвестен:
        // TFTP по RFC 1350 его не передаёт, тогда полоса остаётся «бегунком».
        let (prog_base, prog_total) = match session.as_ref() {
            Some(s) if fed => (
                s.files[..s.next].iter().map(|f| f.1).sum::<u64>(),
                Some(s.files.iter().map(|f| f.1).sum::<u64>()),
            ),
            _ => (0, None),
        };
        match prog_total {
            Some(t) => log(&format!("  общий размер известен из списка отправителя: {t} байт")),
            None => log(
                "  общий размер неизвестен: список файлов от отправителя не получен \
                 (обычный TFTP-клиент, либо отправитель не tftp-rs / старой версии)",
            ),
        }
        let mut file_progress = |got: u64, _: Option<u64>| progress(prog_base + got, prog_total);
        let mut hw = HashingWriter {
            inner: out,
            hasher: if fed { session.as_mut().map(|s| &mut s.hasher) } else { None },
            size: 0,
        };
        let res = if mode == Mode::Netascii {
            let mut dec = NetasciiDecoder::new(&mut hw);
            recv_blocks_deferred(
                &dsock,
                from,
                build_ack(0).to_vec(),
                Some(from),
                stop,
                &mut dec,
                &mut log,
                &mut file_progress,
            )
            .and_then(|r| dec.finish().map(|_| r).map_err(TftpError::from))
        } else {
            recv_blocks_deferred(
                &dsock,
                from,
                build_ack(0).to_vec(),
                Some(from),
                stop,
                &mut hw,
                &mut log,
                &mut file_progress,
            )
        };
        let received = hw.size;
        drop(hw);

        match res {
            Ok(rx) => {
                let n = rx.total;
                // учитываем файл в общем хэше; итог выносится, когда принят последний файл списка
                let mut problem: Option<String> = start_problem;
                let mut verdict_now: Option<Result<(), String>> = None;
                if let Some(sess) = session.as_mut().filter(|_| in_session) {
                    let had = sess.verdict.is_some();
                    if let Some(p) = sess.finish_file(&filename, fed, received) {
                        problem = Some(p);
                    }
                    if !had {
                        verdict_now = sess.verdict.clone();
                    }
                }
                match std::fs::rename(&tmp, &target) {
                    Ok(()) => {
                        // последний ACK — после сохранения: отправитель сразу переходит к следующему шагу
                        if let Err(e) = ack_final(&dsock, &rx) {
                            log(&format!("Ошибка: не удалось отправить последний ACK: {e}"));
                        }
                        let note = if in_session { "" } else { ", контрольная сумма не проверялась" };
                        log(&format!("✓ {filename}: {n} байт{note} → {}", target.display()));
                        if let Some(p) = problem {
                            log(&format!("Ошибка: {p}"));
                        }
                        received_files.push(target.clone());
                        last_done = Some((from, filename, Instant::now()));
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp);
                        fail_final(&dsock, &rx, 0, "Cannot store file");
                        log(&format!("Ошибка: не удалось сохранить {}: {e}", target.display()));
                    }
                }
                match verdict_now {
                    Some(Ok(())) => {
                        let cnt = session.as_ref().map(|s| s.files.len()).unwrap_or(0);
                        log(&format!("✓ Общая контрольная сумма совпала (файлов: {cnt})"));
                    }
                    Some(Err(m)) => log(&format!("Ошибка: {m}")),
                    None => {}
                }
            }
            Err(TftpError::Cancelled) => {
                // остановка пользователем: недокачанный файл не оставляем, отправитель уже уведомлён
                let _ = std::fs::remove_file(&tmp);
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                if let Some(sess) = session.as_mut().filter(|_| in_session) {
                    sess.abort_file(&filename, &e.to_string());
                }
                // ошибку 3 при сбое записи recv_blocks уже отправил отправителю
                log(&format!("Ошибка приёма {filename}: {e}"));
            }
        }
    }
    // Сюда попадаем только по `stop`: всё, что успело прийти, удаляем.
    let mut removed = 0usize;
    for f in received_files.iter().rev() {
        match std::fs::remove_file(f) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => log(&format!("Ошибка: не удалось удалить {}: {e}", f.display())),
        }
    }
    // созданные нами папки — от самых глубоких; непустые (там чужие файлы) remove_dir не тронет
    for d in created_dirs.iter().rev() {
        let _ = std::fs::remove_dir(d);
    }
    if removed > 0 {
        log(&format!("Удалено принятых файлов: {removed}"));
    }
    log("Приём остановлен");
    Ok(())
}

// ============================= ТЕСТЫ =============================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU16;

    /// Каждому тесту — свой порт и своя папка, чтобы тесты могли идти параллельно.
    static NEXT_PORT: AtomicU16 = AtomicU16::new(47100);
    fn port() -> u16 {
        NEXT_PORT.fetch_add(1, Ordering::SeqCst)
    }

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("tftp_test_{}_{tag}_{}", std::process::id(), port()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Bg {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Bg {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// Обычный TFTP-сервер (без наших расширений).
    fn start_server(port: u16, root: &Path) -> Bg {
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, root) = (stop.clone(), root.to_path_buf());
        let handle = std::thread::spawn(move || {
            let _ = run_server("127.0.0.1", port, root, s2, |_| {});
        });
        std::thread::sleep(Duration::from_millis(200));
        Bg { stop, handle: Some(handle) }
    }

    /// Получатель нашей программы («Начать приём»).
    fn start_receiver(port: u16, dir: &Path) -> Bg {
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, dir) = (stop.clone(), dir.to_path_buf());
        let handle = std::thread::spawn(move || {
            let _ = receive_loop("127.0.0.1", port, &dir, &s2, |_| {}, |_, _| {});
        });
        std::thread::sleep(Duration::from_millis(200));
        Bg { stop, handle: Some(handle) }
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn enc(input: &[u8], native_crlf: bool) -> Vec<u8> {
        let mut r = Cursor::new(input.to_vec());
        let mut e = NetasciiEncoder::with_newline(&mut r, native_crlf);
        let mut out = Vec::new();
        let mut buf = [0u8; 7]; // маленький буфер проверяет, что остаток не теряется
        loop {
            let n = e.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    fn dec(chunks: &[&[u8]], native_crlf: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        {
            let mut d = NetasciiDecoder::with_newline(&mut out, native_crlf);
            for c in chunks {
                d.write_all(c).unwrap();
            }
            d.finish().unwrap();
        }
        out
    }

    // ---------- netascii ----------

    #[test]
    fn netascii_encode_unix() {
        assert_eq!(enc(b"a\nb\rc\r\nd", false), b"a\r\nb\r\0c\r\0\r\nd");
        assert_eq!(enc(b"\r", false), b"\r\0");
        assert_eq!(enc(b"", false), b"");
    }

    #[test]
    fn netascii_encode_windows_host() {
        assert_eq!(enc(b"a\r\nb\nc\rd", true), b"a\r\nb\r\nc\r\0d");
        assert_eq!(enc(b"x\r", true), b"x\r\0"); // CR в самом конце файла
    }

    #[test]
    fn netascii_decode_and_split_cr() {
        assert_eq!(dec(&[b"a\r\nb\r\0c"], false), b"a\nb\rc");
        assert_eq!(dec(&[b"a\r", b"\nb\r", b"\0c"], false), b"a\nb\rc"); // пара CR/LF разорвана границей блоков
        assert_eq!(dec(&[b"a\r\nb"], true), b"a\r\nb");
        assert_eq!(dec(&[b"end\r"], false), b"end\r"); // CR без пары в конце потока не теряется
    }

    #[test]
    fn netascii_roundtrip() {
        let text = b"line1\nline2\r\n\r\rline5\n".to_vec();
        for native in [false, true] {
            let wire = enc(&text, native);
            let back = dec(&[&wire], native);
            // на Windows-хосте одиночный LF становится CR LF — это ожидаемо; проверяем только Unix точно
            if !native {
                assert_eq!(back, text);
            }
        }
    }

    // ---------- обмен с обычным сервером ----------

    #[test]
    fn octet_put_get_all_sizes() {
        let tmp = TmpDir::new("octet");
        let root = tmp.path().join("srv");
        std::fs::create_dir_all(&root).unwrap();
        let p = port();
        let _srv = start_server(p, &root);
        for &n in &[0usize, 1, 511, 512, 513, 1024, 5000] {
            let src = tmp.path().join(format!("src{n}.bin"));
            let data = pattern(n);
            std::fs::write(&src, &data).unwrap();
            put_file("127.0.0.1", p, &format!("f{n}.bin"), &src, |_| {}, |_, _| {}).unwrap();
            assert_eq!(std::fs::read(root.join(format!("f{n}.bin"))).unwrap(), data, "put {n}");
            let dst = tmp.path().join(format!("dst{n}.bin"));
            get_file("127.0.0.1", p, &format!("f{n}.bin"), &dst, |_| {}, |_, _| {}).unwrap();
            assert_eq!(std::fs::read(&dst).unwrap(), data, "get {n}");
        }
    }

    #[test]
    fn netascii_put_get() {
        let tmp = TmpDir::new("nasc");
        let root = tmp.path().join("srv");
        std::fs::create_dir_all(&root).unwrap();
        let p = port();
        let _srv = start_server(p, &root);
        // большой текст, чтобы CR LF попадали и на границы блоков
        let text: Vec<u8> = (0..3000).flat_map(|i| format!("строка {i}\n").into_bytes()).collect();
        let src = tmp.path().join("t.txt");
        std::fs::write(&src, &text).unwrap();
        put_file_mode("127.0.0.1", p, "t.txt", &src, Mode::Netascii, |_| {}, |_, _| {}).unwrap();
        assert_eq!(std::fs::read(root.join("t.txt")).unwrap(), text);
        let dst = tmp.path().join("t2.txt");
        get_file_mode("127.0.0.1", p, "t.txt", &dst, Mode::Netascii, |_| {}, |_, _| {}).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), text);
    }

    // ---------- «сырой» клиент: проверка байтов на проводе ----------

    fn raw_client() -> UdpSocket {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s
    }

    fn recv(s: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
        let mut b = [0u8; 2048];
        s.recv_from(&mut b).ok().map(|(n, a)| (b[..n].to_vec(), a))
    }

    #[test]
    fn mail_and_unknown_modes_get_error_4() {
        let tmp = TmpDir::new("mode");
        let p = port();
        let _srv = start_server(p, tmp.path());
        for mode in ["mail", "bogus"] {
            let c = raw_client();
            let mut rq = vec![0, OP_WRQ as u8];
            rq.extend_from_slice(b"x.txt\0");
            rq.extend_from_slice(mode.as_bytes());
            rq.push(0);
            c.send_to(&rq, ("127.0.0.1", p)).unwrap();
            let (pkt, _) = recv(&c).expect("ответ на запрос");
            assert_eq!(&pkt[..4], &[0, 5, 0, 4], "режим {mode}: ожидалась ERROR 4");
        }
    }

    #[test]
    fn mode_is_case_insensitive_and_options_are_ignored() {
        let tmp = TmpDir::new("opts");
        std::fs::write(tmp.path().join("a.bin"), pattern(1500)).unwrap();
        let p = port();
        let _srv = start_server(p, tmp.path());
        let c = raw_client();
        // RRQ с режимом «OcTeT» и опциями RFC 2347: сервер без поддержки опций обязан ответить обычным DATA 1
        let mut rq = vec![0, OP_RRQ as u8];
        rq.extend_from_slice(b"a.bin\0OcTeT\0blksize\01428\0tsize\00\0");
        c.send_to(&rq, ("127.0.0.1", p)).unwrap();
        let (pkt, srv_tid) = recv(&c).expect("DATA");
        assert_eq!(&pkt[..4], &[0, 3, 0, 1], "ожидался DATA 1, а не OACK");
        assert_eq!(pkt.len(), 4 + 512);
        assert_ne!(srv_tid.port(), p, "у передачи должен быть свой TID");
    }

    #[test]
    fn foreign_tid_gets_error_5_and_transfer_survives() {
        let tmp = TmpDir::new("tid");
        std::fs::write(tmp.path().join("a.bin"), pattern(600)).unwrap();
        let p = port();
        let _srv = start_server(p, tmp.path());
        let c = raw_client();
        let mut rq = vec![0, OP_RRQ as u8];
        rq.extend_from_slice(b"a.bin\0octet\0");
        c.send_to(&rq, ("127.0.0.1", p)).unwrap();
        let (_, tid) = recv(&c).unwrap();
        // посторонний сокет пишет на TID сервера
        let evil = raw_client();
        evil.send_to(&[0, 4, 0, 1], tid).unwrap();
        let (pkt, _) = recv(&evil).expect("ответ постороннему");
        assert_eq!(&pkt[..4], &[0, 5, 0, 5], "ожидалась ERROR 5");
        // настоящий клиент спокойно дочитывает файл
        c.send_to(&[0, 4, 0, 1], tid).unwrap();
        let (pkt, _) = recv(&c).unwrap();
        assert_eq!(&pkt[..4], &[0, 3, 0, 2]);
        assert_eq!(pkt.len(), 4 + (600 - 512));
    }

    #[test]
    fn lost_final_ack_is_re_sent_dally() {
        let tmp = TmpDir::new("dally");
        let p = port();
        let _srv = start_server(p, tmp.path());
        let c = raw_client();
        let mut rq = vec![0, OP_WRQ as u8];
        rq.extend_from_slice(b"d.bin\0octet\0");
        c.send_to(&rq, ("127.0.0.1", p)).unwrap();
        let (ack0, tid) = recv(&c).unwrap();
        assert_eq!(ack0, vec![0, 4, 0, 0]);
        let data = [&[0u8, 3, 0, 1][..], b"short"].concat();
        c.send_to(&data, tid).unwrap();
        let (ack1, _) = recv(&c).unwrap();
        assert_eq!(ack1, vec![0, 4, 0, 1]);
        // «ACK потерялся»: клиент повторяет последний DATA — сервер обязан ответить тем же ACK
        c.send_to(&data, tid).unwrap();
        let (again, _) = recv(&c).expect("повторный ACK после потери");
        assert_eq!(again, vec![0, 4, 0, 1]);
        assert_eq!(std::fs::read(tmp.path().join("d.bin")).unwrap(), b"short");
    }

    #[test]
    fn unexpected_opcode_gets_error_4() {
        let tmp = TmpDir::new("badop");
        std::fs::write(tmp.path().join("a.bin"), pattern(2000)).unwrap();
        let p = port();
        let _srv = start_server(p, tmp.path());
        let c = raw_client();
        let mut rq = vec![0, OP_RRQ as u8];
        rq.extend_from_slice(b"a.bin\0octet\0");
        c.send_to(&rq, ("127.0.0.1", p)).unwrap();
        let (_, tid) = recv(&c).unwrap();
        c.send_to(&[0, 3, 0, 1, 9, 9], tid).unwrap(); // DATA там, где ждут ACK
        let (pkt, _) = recv(&c).unwrap();
        assert_eq!(&pkt[..4], &[0, 5, 0, 4]);
    }

    // ---------- наши расширения ----------

    #[test]
    fn send_path_to_plain_server_is_pure_rfc1350() {
        let tmp = TmpDir::new("plain");
        let root = tmp.path().join("srv");
        std::fs::create_dir_all(&root).unwrap();
        let src = tmp.path().join("hello.txt");
        std::fs::write(&src, b"hello world").unwrap();
        let p = port();
        let _srv = start_server(p, &root);
        let mut lines = Vec::new();
        send_path("127.0.0.1", p, &src, |l| lines.push(l.to_string()), |_, _| {}).unwrap();
        let names: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("hello.txt")], "служебных файлов быть не должно");
        assert_eq!(std::fs::read(root.join("hello.txt")).unwrap(), b"hello world");
        assert!(lines.iter().any(|l| l.contains("обычный TFTP-сервер")), "{lines:?}");
    }

    #[test]
    fn send_path_to_our_receiver_verifies() {
        let tmp = TmpDir::new("ext");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(proj.join("sub")).unwrap();
        std::fs::write(proj.join("a.bin"), pattern(1300)).unwrap();
        std::fs::write(proj.join("sub").join("b.bin"), pattern(512)).unwrap();
        std::fs::write(proj.join("sub").join(".hidden"), b"").unwrap();
        let p = port();
        let _rx = start_receiver(p, &dst);
        let mut lines = Vec::new();
        send_path("127.0.0.1", p, &proj, |l| lines.push(l.to_string()), |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dst.join("proj/a.bin")).unwrap(), pattern(1300));
        assert_eq!(std::fs::read(dst.join("proj/sub/b.bin")).unwrap(), pattern(512));
        assert!(dst.join("proj/sub/.hidden").exists());
        assert!(lines.iter().any(|l| l.contains("Контрольная сумма совпала")), "{lines:?}");
    }

    #[test]
    fn our_receiver_accepts_plain_and_netascii_clients() {
        let tmp = TmpDir::new("rx");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let p = port();
        let _rx = start_receiver(p, &dst);
        let src = tmp.path().join("t.txt");
        std::fs::write(&src, b"one\ntwo\n").unwrap();
        // обычный клиент без всяких расширений
        put_file("127.0.0.1", p, "plain.txt", &src, |_| {}, |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dst.join("plain.txt")).unwrap(), b"one\ntwo\n");
        // netascii
        put_file_mode("127.0.0.1", p, "ascii.txt", &src, Mode::Netascii, |_| {}, |_, _| {}).unwrap();
        assert_eq!(std::fs::read(dst.join("ascii.txt")).unwrap(), b"one\ntwo\n");
        // чтение файлов с приёмника запрещено ошибкой 2
        let e = get_file("127.0.0.1", p, "plain.txt", &tmp.path().join("x"), |_| {}, |_, _| {}).unwrap_err();
        assert!(matches!(e, TftpError::Remote(2, _)), "{e:?}");
        // mail отклоняется
        let c = raw_client();
        let mut rq = vec![0, OP_WRQ as u8];
        rq.extend_from_slice(b"m.txt\0mail\0");
        c.send_to(&rq, ("127.0.0.1", p)).unwrap();
        let (pkt, _) = recv(&c).unwrap();
        assert_eq!(&pkt[..4], &[0, 5, 0, 4]);
    }

    /// Запускает приём и даёт узнать, завершился ли он сам.
    fn start_receiver_watched(port: u16, dir: &Path, log: Arc<Mutex<Vec<String>>>) -> (Bg, Arc<AtomicBool>) {
        let stop = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));
        let (s2, e2, d2) = (stop.clone(), exited.clone(), dir.to_path_buf());
        let handle = std::thread::spawn(move || {
            let _ = receive_loop("127.0.0.1", port, &d2, &s2, move |m| log.lock().unwrap().push(m.to_string()), |_, _| {});
            e2.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(200));
        (Bg { stop, handle: Some(handle) }, exited)
    }

    fn wait_flag(f: &AtomicBool, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if f.load(Ordering::SeqCst) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        f.load(Ordering::SeqCst)
    }

    #[test]
    fn plain_client_does_not_disturb_session_and_receiver_finishes_by_itself() {
        let tmp = TmpDir::new("sess");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let src = tmp.path().join("a.bin");
        std::fs::write(&src, pattern(700)).unwrap();
        let p = port();
        let rx_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (_bg, exited) = start_receiver_watched(p, &dst, rx_log.clone());

        // обычный клиент: одиночный файл (без списка), чтение запрещено — приём продолжает слушать
        put_file("127.0.0.1", p, "plain1.bin", &src, |_| {}, |_, _| {}).unwrap();
        let _ = get_file("127.0.0.1", p, "plain1.bin", &tmp.path().join("x"), |_| {}, |_, _| {});
        assert!(!exited.load(Ordering::SeqCst), "от обычного клиента приём сам не завершается");

        // tftp-rs: всё принято и проверено — приём завершается сам
        send_path("127.0.0.1", p, &src, |_| {}, |_, _| {}).unwrap();
        assert!(wait_flag(&exited, 5), "после успешной проверки приём должен завершиться");

        let log = rx_log.lock().unwrap().clone();
        assert!(!log.iter().any(|l| l.contains("Ошибка")), "{log:#?}");
        assert!(log.iter().any(|l| l.contains("чтение запрещено")), "{log:#?}");
        assert!(dst.join("plain1.bin").exists() && dst.join("a.bin").exists());
    }

    #[test]
    fn send_paths_several_files_and_folders_in_one_session() {
        let tmp = TmpDir::new("multi");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let x = tmp.path().join("x.bin");
        let y = tmp.path().join("y.txt");
        let d = tmp.path().join("docs");
        std::fs::create_dir_all(d.join("in")).unwrap();
        std::fs::write(&x, pattern(1300)).unwrap();
        std::fs::write(&y, b"hello").unwrap();
        std::fs::write(d.join("in").join("z.bin"), pattern(2000)).unwrap();
        let p = port();
        let rx_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (_bg, exited) = start_receiver_watched(p, &dst, rx_log.clone());
        let mut tx_log = Vec::new();
        send_paths("127.0.0.1", p, &[x, d, y], |l| tx_log.push(l.to_string()), |_, _| {}).unwrap();
        assert!(wait_flag(&exited, 5));
        assert_eq!(std::fs::read(dst.join("x.bin")).unwrap(), pattern(1300));
        assert_eq!(std::fs::read(dst.join("y.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(dst.join("docs/in/z.bin")).unwrap(), pattern(2000));
        assert!(tx_log.iter().any(|l| l.contains("Контрольная сумма совпала") && l.contains("файлов: 3")), "{tx_log:?}");
    }

    #[test]
    fn send_paths_rejects_duplicate_names() {
        let tmp = TmpDir::new("dup");
        std::fs::create_dir_all(tmp.path().join("p1")).unwrap();
        std::fs::create_dir_all(tmp.path().join("p2")).unwrap();
        let a1 = tmp.path().join("p1/a.bin");
        let a2 = tmp.path().join("p2/a.bin");
        std::fs::write(&a1, b"1").unwrap();
        std::fs::write(&a2, b"2").unwrap();
        let e = send_paths("127.0.0.1", port(), &[a1, a2], |_| {}, |_, _| {}).unwrap_err();
        assert!(e.to_string().contains("одно имя"), "{e}");
    }

    #[test]
    fn receiver_reports_real_progress_for_our_sender() {
        let tmp = TmpDir::new("prog");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("a.bin"), pattern(1300)).unwrap();
        std::fs::write(proj.join("b.bin"), pattern(3000)).unwrap();
        let p = port();
        let seen: Arc<Mutex<Vec<(u64, Option<u64>)>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (v2, s2, d2) = (seen.clone(), stop.clone(), dst.clone());
        let h = std::thread::spawn(move || {
            let _ = receive_loop("127.0.0.1", p, &d2, &s2, |_| {}, move |got, tot| v2.lock().unwrap().push((got, tot)));
        });
        let _bg = Bg { stop, handle: Some(h) };
        std::thread::sleep(Duration::from_millis(200));
        send_path("127.0.0.1", p, &proj, |_| {}, |_, _| {}).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let v = seen.lock().unwrap().clone();
        assert!(!v.is_empty());
        assert!(v.iter().all(|(_, t)| *t == Some(4300)), "везде известен общий размер: {v:?}");
        assert!(v.windows(2).all(|w| w[0].0 <= w[1].0), "прогресс не должен идти назад: {v:?}");
        assert_eq!(v.last().unwrap().0, 4300, "в конце — весь объём");
        assert!(v.iter().any(|(g, _)| *g > 1300), "второй файл считается от конца первого: {v:?}");
    }

    #[test]
    fn sender_cancel_stops_sending_and_receiver_keeps_listening() {
        let tmp = TmpDir::new("scancel");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let big = tmp.path().join("big.bin");
        std::fs::write(&big, pattern(4_000_000)).unwrap();
        let p = port();
        let rx_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (_bg, exited) = start_receiver_watched(p, &dst, rx_log.clone());

        let cancel = AtomicBool::new(false);
        let t0 = Instant::now();
        let r = send_paths_cancel("127.0.0.1", p, &[big.clone()], &cancel, |_| {}, |sent, _| {
            if sent > 100_000 {
                cancel.store(true, Ordering::SeqCst);
            }
        });
        assert!(matches!(r, Err(TftpError::Cancelled)), "{r:?}");
        assert!(t0.elapsed() < Duration::from_secs(3), "остановка должна быть мгновенной");
        std::thread::sleep(Duration::from_millis(400));
        assert!(!dst.join("big.bin").exists() && !dst.join("big.bin.part").exists(), "недокачанного файла быть не должно");
        assert!(!exited.load(Ordering::SeqCst), "получатель продолжает слушать");
        // после отмены можно отправить снова
        let small = tmp.path().join("small.bin");
        std::fs::write(&small, pattern(700)).unwrap();
        send_paths("127.0.0.1", p, &[small], |_| {}, |_, _| {}).unwrap();
        assert!(wait_flag(&exited, 5));
        assert_eq!(std::fs::read(dst.join("small.bin")).unwrap(), pattern(700));
        let log = rx_log.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.contains("отменила")), "{log:#?}");
    }

    #[test]
    fn receiver_stop_mid_transfer_aborts_and_deletes_everything_received() {
        let tmp = TmpDir::new("rstop");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&dst).unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("a.bin"), pattern(1000)).unwrap();
        std::fs::write(proj.join("z.bin"), pattern(4_000_000)).unwrap();
        let p = port();
        let stop = Arc::new(AtomicBool::new(false));
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let (s2, s3, l2, d2) = (stop.clone(), stop.clone(), log.clone(), dst.clone());
        let h = std::thread::spawn(move || {
            let _ = receive_loop(
                "127.0.0.1",
                p,
                &d2,
                &s2,
                move |m| l2.lock().unwrap().push(m.to_string()),
                move |got, _| {
                    if got > 500_000 {
                        s3.store(true, Ordering::SeqCst); // «Остановить» нажато, когда z.bin принят наполовину
                    }
                },
            );
        });
        let bg = Bg { stop, handle: Some(h) };
        std::thread::sleep(Duration::from_millis(200));

        let t0 = Instant::now();
        let r = send_path("127.0.0.1", p, &proj, |_| {}, |_, _| {});
        assert!(matches!(r, Err(TftpError::Remote(0, _))), "отправитель должен получить ошибку: {r:?}");
        assert!(t0.elapsed() < Duration::from_secs(5), "без ожидания таймаутов");
        drop(bg); // ждём завершения потока приёма
        let left: Vec<_> = std::fs::read_dir(&dst).unwrap().collect();
        assert!(left.is_empty(), "всё принятое удалено, включая папку proj: {left:?}");
        let log = log.lock().unwrap().clone();
        assert!(log.iter().any(|l| l.contains("Удалено принятых файлов: 1")), "{log:#?}");
    }

    /// Длинный файл: счётчик блоков переходит через 65535 → 0 (≈34 МБ; медленно, запуск: `cargo test -- --ignored`).
    #[test]
    #[ignore]
    fn block_number_wraps_around() {
        let tmp = TmpDir::new("wrap");
        let root = tmp.path().join("srv");
        std::fs::create_dir_all(&root).unwrap();
        let p = port();
        let _srv = start_server(p, &root);
        let n = 65_535 * BLOCK_SIZE + 700;
        let data = pattern(n);
        let src = tmp.path().join("big.bin");
        std::fs::write(&src, &data).unwrap();
        put_file("127.0.0.1", p, "big.bin", &src, |_| {}, |_, _| {}).unwrap();
        assert!(std::fs::read(root.join("big.bin")).unwrap() == data);
        let dst = tmp.path().join("big2.bin");
        get_file("127.0.0.1", p, "big.bin", &dst, |_| {}, |_, _| {}).unwrap();
        assert!(std::fs::read(&dst).unwrap() == data);
    }
}
