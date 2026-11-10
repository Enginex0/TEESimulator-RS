use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

const KMSG_PATH: &str = "/dev/kmsg";
const TAG: &str = "TEESimulator";

pub struct KmsgLayer {
    writer: Mutex<Option<File>>,
}

impl KmsgLayer {
    pub fn new() -> Self {
        let file = OpenOptions::new().write(true).open(KMSG_PATH).ok();
        Self {
            writer: Mutex::new(file),
        }
    }
}

fn syslog_priority(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        Level::DEBUG | Level::TRACE => 7,
    }
}

struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            fields: String::new(),
        }
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let raw = format!("{:?}", value);
            // Strip surrounding debug quotes if present
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

impl<S: Subscriber> Layer<S> for KmsgLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut guard = match self.writer.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let file = match guard.as_mut() {
            Some(f) => f,
            None => return,
        };

        let priority = syslog_priority(event.metadata().level());
        let mut visitor = MessageVisitor::new();
        event.record(&mut visitor);

        let line = if visitor.fields.is_empty() {
            format!("<{}>{}: {}\n", priority, TAG, visitor.message)
        } else {
            format!(
                "<{}>{}: {} {}\n",
                priority, TAG, visitor.message, visitor.fields
            )
        };

        let _ = file.write_all(line.as_bytes());
    }
}
