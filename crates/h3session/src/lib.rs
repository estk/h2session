#[cfg(feature = "tracing")]
macro_rules! trace_debug {
    ($($arg:tt)*) => { ::tracing::debug!($($arg)*) }
}
#[cfg(not(feature = "tracing"))]
macro_rules! trace_debug {
    ($($arg:tt)*) => {};
}
pub(crate) use trace_debug;

mod frame;
mod qpack;
mod state;

pub use frame::{Frame, FrameType};
pub use qpack::QpackDecoder;
pub use state::{H3ConnectionState, H3StreamState, ParsedH3Message};
