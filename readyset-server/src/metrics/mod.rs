//! Support for recording and exporting in-memory metrics using the [`metrics`] crate

use std::sync::OnceLock;

pub use crate::metrics::composite_recorder::{CompositeMetricsRecorder, RecorderType};
pub use crate::metrics::noria_recorder::NoriaMetricsRecorder;
pub use crate::metrics::recorders::{
    MetricsRecorder, PrometheusBuilder, PrometheusHandle, PrometheusRecorder,
};

mod composite_recorder;
mod noria_recorder;
mod prometheus_recorder;
mod recorders;

/// The type of the static, globally accessible metrics recorder.
type GlobalRecorder = CompositeMetricsRecorder;
static METRICS_RECORDER: OnceLock<&'static GlobalRecorder> = OnceLock::new();

/// Installs a new global recorder
pub fn install_global_recorder(rec: GlobalRecorder) {
    let rec = Box::leak(Box::new(rec));
    METRICS_RECORDER
        .set(rec)
        .expect("metrics already initialized");
    metrics::set_global_recorder(&*rec).expect("Would fail on OnceCell");
}

/// Gets an [`Option`] with the static reference to the installed metrics recorder.
/// This method returns [`None`] if `install()` has not been called yet.
pub fn get_global_recorder() -> Option<&'static GlobalRecorder> {
    METRICS_RECORDER.get().cloned()
}

/// A metrics recorder that can be cleared.
pub trait Clear {
    /// Clear the data saved in the recorder.
    /// Returns [`true`] if the recorder was successfully cleared; or [`false`] otherwise.
    fn clear(&self) -> bool;
}

/// A metrics recorder that can be rendered.
/// We do not use [`std::fmt::Display`] since we might be extending
/// [`Recorder`]s from other libraries as well.
pub trait Render {
    /// Renders the metrics stored in the recorder.
    fn render(&self) -> String;
}
