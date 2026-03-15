use std::ffi::CString;
use std::fmt::Write as _;
use std::sync::OnceLock;

use tracing::Level;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

static INIT: OnceLock<()> = OnceLock::new();
/// Keep the ident CString alive for the lifetime of the process (syslog
/// retains a pointer to it).
static IDENT: OnceLock<CString> = OnceLock::new();

/// Syslog facility for PAM modules (`LOG_AUTHPRIV`).
pub const FACILITY_AUTHPRIV: libc::c_int = 10 << 3;
/// Syslog facility for daemon/service components (`LOG_DAEMON`).
pub const FACILITY_DAEMON: libc::c_int = 3 << 3;

/// Initialise syslog-based tracing for an sssd-oidc component.
///
/// - `ident` — syslog identifier (e.g. `"sssd_oidc"`, `"pam_oidc"`).
/// - `facility` — syslog facility (e.g. [`FACILITY_DAEMON`], [`FACILITY_AUTHPRIV`]).
///
/// The default log level is `WARN` (matching SSSD's `debug_level=2`).
/// Override with the `SSSD_OIDC_LOG` environment variable set to one of:
/// `error`, `warn`, `info`, `debug`, `trace`, `off`.
///
/// Safe to call multiple times; only the first call takes effect.
/// If the process already has a tracing subscriber, logging is silently
/// skipped (NSS/PAM modules are loaded into arbitrary processes).
pub fn init(ident: &str, facility: libc::c_int) {
    INIT.get_or_init(|| {
        let ident_c = IDENT.get_or_init(|| {
            CString::new(ident).unwrap_or_else(|_| CString::new("sssd_oidc").unwrap())
        });

        unsafe {
            libc::openlog(ident_c.as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, facility);
        }

        let level = parse_level();

        let _ = tracing_subscriber::registry()
            .with(level)
            .with(SyslogLayer)
            .try_init();
    });
}

/// Parse `SSSD_OIDC_LOG` env var into a tracing level filter.
fn parse_level() -> tracing_subscriber::filter::LevelFilter {
    use tracing_subscriber::filter::LevelFilter;
    match std::env::var("SSSD_OIDC_LOG")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        "off" => LevelFilter::OFF,
        _ => LevelFilter::WARN,
    }
}

/// A [`tracing_subscriber::Layer`] that forwards events to syslog(3).
///
/// Message format: `[module::path] message key=value ...`
struct SyslogLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SyslogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let priority = match *event.metadata().level() {
            Level::ERROR => libc::LOG_ERR,
            Level::WARN => libc::LOG_WARNING,
            Level::INFO => libc::LOG_INFO,
            Level::DEBUG | Level::TRACE => libc::LOG_DEBUG,
        };

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let module = event.metadata().module_path().unwrap_or("sssd_oidc");

        let msg = match visitor.message {
            Some(ref m) if visitor.fields.is_empty() => format!("[{}] {}", module, m),
            Some(ref m) => format!("[{}] {} {}", module, m, visitor.fields),
            None if visitor.fields.is_empty() => format!("[{}] (event)", module),
            None => format!("[{}] {}", module, visitor.fields),
        };

        if let Ok(c_msg) = CString::new(msg) {
            unsafe {
                libc::syslog(priority, c"%s".as_ptr(), c_msg.as_ptr());
            }
        }
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
        } else {
            let sep = if self.fields.is_empty() { "" } else { " " };
            write!(self.fields, "{}{}={:?}", sep, field.name(), value).ok();
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            let sep = if self.fields.is_empty() { "" } else { " " };
            write!(self.fields, "{}{}={}", sep, field.name(), value).ok();
        }
    }
}
