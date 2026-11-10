use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

struct RotatingState {
    dir: PathBuf,
    current: Option<File>,
    current_size: u64,
    max_size: u64,
    max_files: usize,
}

pub struct RotatingFileLayer {
    state: Mutex<RotatingState>,
}

impl RotatingFileLayer {
    pub fn new(dir: &str, max_size: u64, max_files: usize) -> Self {
        let dir = PathBuf::from(dir);
        let _ = fs::create_dir_all(&dir);
        let (file, size) = open_current_log(&dir);
        Self {
            state: Mutex::new(RotatingState {
                dir,
                current: file,
                current_size: size,
                max_size,
                max_files,
            }),
        }
    }
}

fn open_current_log(dir: &Path) -> (Option<File>, u64) {
    let path = dir.join("certgen.log");
    let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok();
    (file, size)
}

fn rotate(state: &mut RotatingState) {
    // Close current handle before renaming
    state.current.take();

    let dir = &state.dir;
    // Delete the oldest rotated file before shifting
    let oldest = dir.join(format!("certgen.log.{}", state.max_files));
    if oldest.exists() {
        let _ = fs::remove_file(&oldest);
    }
    // Shift older files up: .{N} -> .{N+1}
    for i in (1..state.max_files).rev() {
        let from = dir.join(format!("certgen.log.{}", i));
        let to = dir.join(format!("certgen.log.{}", i + 1));
        if from.exists() {
            let _ = fs::rename(&from, &to);
        }
    }
    // Current -> .1
    let current_path = dir.join("certgen.log");
    let first_rotated = dir.join("certgen.log.1");
    if current_path.exists() {
        let _ = fs::rename(&current_path, &first_rotated);
    }

    let (file, size) = open_current_log(dir);
    state.current = file;
    state.current_size = size;
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn level_str(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

struct LogVisitor {
    message: String,
    fields: String,
}

impl LogVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            fields: String::new(),
        }
    }
}

impl Visit for LogVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let raw = format!("{:?}", value);
            self.message = raw
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&raw)
                .to_string();
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            self.fields.push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

impl<S: Subscriber> Layer<S> for RotatingFileLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        if state.current_size >= state.max_size {
            rotate(&mut state);
        }

        let file = match state.current.as_mut() {
            Some(f) => f,
            None => return,
        };

        let ts = epoch_secs();
        let lvl = level_str(event.metadata().level());
        let target = event.metadata().target();

        let mut visitor = LogVisitor::new();
        event.record(&mut visitor);

        let line = if visitor.fields.is_empty() {
            format!("{} [{}] {}: {}\n", ts, lvl, target, visitor.message)
        } else {
            format!(
                "{} [{}] {}: {} {}\n",
                ts, lvl, target, visitor.message, visitor.fields
            )
        };

        if file.write_all(line.as_bytes()).is_ok() {
            state.current_size += line.len() as u64;
        }
    }
}
