use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use database_utils::DatabaseURL;
use metrics::Unit;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::benchmark::{BenchmarkControl, BenchmarkResults, DeploymentParameters, MetricGoal};
use crate::utils::generate::DataGenerator;
use crate::utils::prometheus::ForwardPrometheusMetrics;
use crate::{benchmark_counter, benchmark_histogram};

#[derive(Parser, Clone, Serialize, Deserialize)]
pub struct ScaleConnections {
    /// The number of views to create in the experiment.
    #[arg(long, default_value = "1")]
    num_connections: usize,

    /// Whether to open all the connections in parallel or serially, closing
    /// each connection before opening the next.
    #[arg(long)]
    parallel: bool,
}

impl BenchmarkControl for ScaleConnections {
    async fn setup(&self, _: &DeploymentParameters) -> Result<()> {
        Ok(())
    }

    async fn reset(&self, _: &DeploymentParameters) -> Result<()> {
        Err(anyhow::anyhow!("reset unsupported"))
    }

    async fn benchmark(&self, deployment: &DeploymentParameters) -> Result<BenchmarkResults> {
        info!(
            "Running benchmark connecting to {} connections.",
            self.num_connections
        );

        let mut connections = Vec::new();
        let mut results = BenchmarkResults::new();
        let duration_data =
            results.entry("connect_time", Unit::Microseconds, MetricGoal::Decreasing);
        for _ in 0..self.num_connections {
            let url = DatabaseURL::from_str(&deployment.target_conn_str)?;

            let start = Instant::now();
            let conn = url.connect(None).await?;
            let connection_time = start.elapsed();

            // Keep the state alive by storing it in the struct.
            if self.parallel {
                connections.push(conn);
            }

            info!(
                "connection:\t{:.1}ms",
                connection_time.as_secs_f64() * 1000.0,
            );

            duration_data.push(connection_time.as_micros() as f64);
            benchmark_histogram!(
                "scale_connections.connection_duration",
                Seconds,
                "The number of seconds spent creating a new connection".into(),
                connection_time.as_secs_f64()
            );

            benchmark_counter!(
                "scale_connections.connections",
                Count,
                "The number of connections the benchmark has executed".into(),
                1
            )
        }

        Ok(results)
    }

    fn labels(&self) -> HashMap<String, String> {
        let mut labels = HashMap::new();
        labels.insert(
            "num_connections".to_string(),
            self.num_connections.to_string(),
        );
        labels.insert("parallel".to_string(), self.parallel.to_string());
        labels
    }

    fn forward_metrics(&self, _: &DeploymentParameters) -> Vec<ForwardPrometheusMetrics> {
        vec![]
    }

    fn name(&self) -> &'static str {
        "scale_connections"
    }

    fn data_generator(&mut self) -> Option<&mut DataGenerator> {
        None
    }
}
