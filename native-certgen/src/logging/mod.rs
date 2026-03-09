mod kmsg;
mod rotating;
pub mod sysfs;
pub mod dump;

use std::path::Path;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const VERBOSE_MARKER: &str = "/data/adb/tricky_store/.verbose";

pub fn init(
    verbose_flag: bool,
    log_dir: &str,
    max_size_mb: u64,
    max_files: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let verbose = verbose_flag || Path::new(VERBOSE_MARKER).exists();

    let (max_size, max_files) = if verbose {
        (5 * 1024 * 1024, 5)
    } else {
        (max_size_mb * 1024 * 1024, max_files)
    };

    let level = if verbose { "trace" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    let kmsg_layer = kmsg::KmsgLayer::new();
    let rotating_layer = rotating::RotatingFileLayer::new(log_dir, max_size, max_files);
    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

    // Idempotent — second call returns Ok instead of propagating SetGlobalDefaultError
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(kmsg_layer)
        .with(rotating_layer)
        .with(stderr_layer)
        .try_init();

    Ok(())
}
