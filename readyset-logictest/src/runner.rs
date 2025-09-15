use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::{io, mem};

use anyhow::{anyhow, bail, Context};
use database_utils::{DatabaseConnection, DatabaseType, DatabaseURL, QueryableConnection, TlsMode};
use itertools::Itertools;
use mysql_srv::MySqlIntermediary;
use readyset_adapter::backend::noria_connector::ReadBehavior;
use readyset_adapter::backend::{BackendBuilder, NoriaConnector};
use readyset_adapter::query_status_cache::QueryStatusCache;
use readyset_adapter::upstream_database::LazyUpstream;
use readyset_adapter::{ReadySetStatusReporter, UpstreamConfig, UpstreamDatabase};
use readyset_client::ReadySetHandle;
use readyset_data::upstream_system_props::{
    init_system_props, UpstreamSystemProperties, DEFAULT_TIMEZONE_NAME,
};
use readyset_data::{Collation, DfType, DfValue};
use readyset_mysql::{MySqlQueryHandler, MySqlUpstream};
use readyset_psql::{PostgreSqlQueryHandler, PostgreSqlUpstream};
use readyset_server::{Builder, ReuseConfigType};
use readyset_sql::ast::Relation;
use readyset_sql::Dialect;
use readyset_sql_parsing::ParsingPreset;
use readyset_util::retry_with_exponential_backoff;
use readyset_util::shared_cache::SharedCache;
use readyset_util::shutdown::ShutdownSender;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, error, info};
use {mysql_async as mysql, tokio_postgres as pgsql};

use crate::ast::{
    Conditional, Query, QueryResults, Record, SortMode, Statement, StatementResult, Value,
};
use crate::parser;

#[derive(Debug, Clone)]
pub struct TestScript {
    path: PathBuf,
    records: Vec<Record>,
}

impl From<Vec<Record>> for TestScript {
    fn from(records: Vec<Record>) -> Self {
        TestScript {
            path: "".into(),
            records,
        }
    }
}

impl FromIterator<Record> for TestScript {
    fn from_iter<T: IntoIterator<Item = Record>>(iter: T) -> Self {
        Self::from(iter.into_iter().collect::<Vec<_>>())
    }
}

impl Extend<Record> for TestScript {
    fn extend<T: IntoIterator<Item = Record>>(&mut self, iter: T) {
        self.records.extend(iter)
    }
}

impl TestScript {
    pub fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        write!(w, "{self}")
    }
}

impl Display for TestScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.records().iter().join("\n"))
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub database_type: DatabaseType,
    pub upstream_database_url: Option<DatabaseURL>,
    /// Should be set to true if `upstream_database_url` points to an existing Readyset instance, in
    /// which case we should not attempt to start a new in-process Readyset instance to test and
    /// should directly test the existing instance.
    pub upstream_database_is_readyset: bool,
    pub replication_url: Option<String>,
    pub parsing_preset: ParsingPreset,
    pub enable_reuse: bool,
    pub time: bool,
    pub verbose: bool,
}

impl RunOptions {
    pub fn default_for_database(database_type: DatabaseType) -> Self {
        Self {
            upstream_database_url: None,
            upstream_database_is_readyset: false,
            enable_reuse: false,
            time: false,
            replication_url: None,
            database_type,
            parsing_preset: ParsingPreset::for_tests(),
            verbose: false,
        }
    }
}

fn compare_results(results: &[Value], expected: &[Value], type_sensitive: bool) -> bool {
    if type_sensitive {
        return results == expected;
    }

    results
        .iter()
        .zip(expected)
        .all(|(res, expected)| res.compare_type_insensitive(expected))
}

/// Establish a connection to the upstream DB server and recreate the test database
pub(crate) async fn recreate_test_database(url: &DatabaseURL) -> anyhow::Result<()> {
    let db_name = url
        .db_name()
        .ok_or_else(|| anyhow!("Must specify database name as part of database URL"))?;
    let mut admin_url = url.clone();
    admin_url.set_db_name(match url.database_type() {
        DatabaseType::PostgreSQL => "postgres".to_owned(),
        DatabaseType::MySQL => "mysql".to_owned(),
    });
    let mut admin_conn = admin_url
        .connect(None)
        .await
        .with_context(|| "connecting to upstream")?;

    admin_conn
        .query_drop(format!("DROP DATABASE IF EXISTS {db_name}"))
        .await
        .with_context(|| "dropping database")?;

    let mut create_database_query = format!("CREATE DATABASE {db_name}");
    if url.is_mysql() {
        create_database_query.push_str(" CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_bin'");
    }
    admin_conn
        .query_drop(create_database_query)
        .await
        .with_context(|| "creating database")?;

    Ok(())
}

impl TestScript {
    pub fn read<R: io::Read>(path: PathBuf, input: R) -> anyhow::Result<Self> {
        let records = parser::read_records(input)?;
        Ok(Self { path, records })
    }

    pub fn open_file(path: PathBuf) -> anyhow::Result<Self> {
        let file = File::open(&path)?;
        Self::read(path, file)
    }

    pub fn name(&self) -> Cow<'_, str> {
        match self.path.file_name() {
            Some(n) => n.to_string_lossy(),
            None => Cow::Borrowed("unknown"),
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn run(&mut self, opts: RunOptions) -> anyhow::Result<()> {
        info!(path = ?self.path, "Running test script");

        // Recreate the test database, unless this is a long-lived remote readyset instance (e.g.
        // running under Antithesis) in which case the state needs to be managed/reset externally;
        // we currently won't do the right thing if we drop and recreate an database out from under
        // the Readyset instance, and Postgres won't even let us do it. See REA-5958.
        if !opts.upstream_database_is_readyset {
            if let Some(upstream_url) = &opts.upstream_database_url {
                recreate_test_database(upstream_url).await?;
            } else if let Some(replication_url) = &opts.replication_url {
                recreate_test_database(&replication_url.parse()?).await?;
            }
        }

        if let Some(upstream_url) = &opts.upstream_database_url {
            let mut conn = upstream_url
                .connect(None)
                .await
                .with_context(|| "connecting to upstream database")?;

            // We expect it's harmless to always enable the built-in citext extension, which fuzz
            // tests might generate.
            if upstream_url.is_postgres() {
                conn.query_drop("create extension if not exists citext")
                    .await?;
            }

            self.run_on_database(&opts, &mut conn, opts.upstream_database_is_readyset)
                .await?;
        } else {
            self.run_on_noria(&opts).await?;
        };

        Ok(())
    }

    /// Run the test script on ReadySet server
    pub async fn run_on_noria(&self, opts: &RunOptions) -> anyhow::Result<()> {
        let authority = Arc::new(
            readyset_client::consensus::AuthorityType::Local.to_authority("", "logictest"),
        );

        let (_noria_handle, shutdown_tx) = self.start_noria_server(opts, authority.clone()).await;
        let (adapter_task, db_url) = self.setup_adapter(opts, authority).await;

        let mut conn = match db_url
            .connect(None)
            .await
            .with_context(|| "connecting to adapter")
        {
            Ok(conn) => conn,
            Err(e) => {
                shutdown_tx.shutdown().await;
                return Err(e);
            }
        };

        if let Err(e) = self.run_on_database(opts, &mut conn, true).await {
            shutdown_tx.shutdown().await;
            return Err(e);
        }

        // After all tests are done, stop the adapter
        adapter_task.abort();
        let _ = adapter_task.await;

        // Stop ReadySet
        shutdown_tx.shutdown().await;

        Ok(())
    }

    async fn update_system_timezone(conn: &mut DatabaseConnection) -> anyhow::Result<()> {
        let timezone_name = if matches!(conn, DatabaseConnection::PostgreSQL(..)) {
            let res = Vec::<Vec<DfValue>>::try_from(conn.simple_query("show timezone").await?)?;
            if let Some(row) = res.into_iter().at_most_one()? {
                let val = row.into_iter().at_most_one()?;
                match &val {
                    Some(v) if v.is_string() => v.as_str().unwrap(),
                    _ => DEFAULT_TIMEZONE_NAME,
                }
                .into()
            } else {
                DEFAULT_TIMEZONE_NAME.into()
            }
        } else {
            // Have yet to implement system timezone support for MySQL
            DEFAULT_TIMEZONE_NAME.into()
        };
        init_system_props(&UpstreamSystemProperties {
            timezone_name,
            ..Default::default()
        })
        .map_err(|e| anyhow!(e))
    }

    fn might_be_timezone_changing_statement(conn: &mut DatabaseConnection, stmt: &str) -> bool {
        let stmt = stmt.to_lowercase();
        stmt.contains("set ")
            && if matches!(conn, DatabaseConnection::PostgreSQL(..)) {
                stmt.contains("timezone")
            } else {
                stmt.contains("time_zone")
            }
    }

    pub async fn run_on_database(
        &self,
        opts: &RunOptions,
        conn: &mut DatabaseConnection,
        is_readyset: bool,
    ) -> anyhow::Result<()> {
        let conditional_skip = |conditionals: &[Conditional]| {
            conditionals.iter().any(|s| match s {
                Conditional::SkipIf(c) if c == "readyset" => is_readyset,
                Conditional::OnlyIf(c) if c == "readyset" => !is_readyset,
                Conditional::SkipIf(c) if c == &opts.database_type.to_string() => true,
                Conditional::OnlyIf(c) if c != &opts.database_type.to_string() => true,
                _ => false,
            })
        };

        let mut update_system_timezone = false;

        for record in &self.records {
            match record {
                Record::Statement(stmt) => {
                    if conditional_skip(&stmt.conditionals) {
                        continue;
                    }
                    if Self::might_be_timezone_changing_statement(conn, stmt.command.as_str()) {
                        update_system_timezone = true;
                    }
                    debug!(command = stmt.command, "Running statement");
                    self.run_statement(stmt, conn)
                        .await
                        .with_context(|| format!("Running statement {}", stmt.command))?
                }

                Record::Query(query) => {
                    if conditional_skip(&query.conditionals) {
                        continue;
                    }

                    let timer = if opts.time {
                        query.label.clone().map(|label| (label, Instant::now()))
                    } else {
                        None
                    };

                    // Failure from noria on a FailNoUpstream query is considered a pass. Passing
                    // is considered a failure.
                    let invert_result = query.conditionals.contains(&Conditional::InvertNoUpstream)
                        && (opts.replication_url.is_none());

                    debug!(query = query.query, "Running query");

                    if update_system_timezone {
                        if let Err(err) = Self::update_system_timezone(conn).await {
                            error!(%err, "Failed to update system timezone")
                        }
                        update_system_timezone = false;
                    }

                    let retries = std::env::var("LOGICTEST_RETRIES")
                        .ok()
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(8);

                    // 100 ms, 2x backoff
                    // 25.5 seconds total
                    match retry_with_exponential_backoff!(
                        {
                            {
                                let query_result = self
                                    .run_query(query, conn, is_readyset)
                                    .await
                                    .with_context(|| format!("Running query {}", query.query));

                                match (query_result, invert_result) {
                                    (Ok(_), true) => {
                                        Err(anyhow!("Expected failure: {}", query.query))
                                    }
                                    (Err(e), false) => Err(e),
                                    _ => Ok(()),
                                }
                            }
                        },
                        retries: retries,
                        delay: 100,
                        backoff: 2,
                    ) {
                        Ok(_) => {
                            if let Some((label, start)) = &timer {
                                let duration = start.elapsed();
                                debug!(label, "Query succeeded in {duration:?}");
                            };
                            Ok(())
                        }
                        Err(e) => Err(e.context(format!("Query failed after {retries} retries"))),
                    }?
                }
                Record::HashThreshold(_) => {}
                Record::Halt { .. } => break,
                Record::Sleep(msecs) => {
                    debug!(msecs, "sleep");
                    sleep(Duration::from_millis(*msecs)).await
                }
                Record::Graphviz => {
                    if is_readyset {
                        let graphviz: Vec<Vec<DfValue>> =
                            conn.simple_query("EXPLAIN GRAPHVIZ").await?.try_into()?;
                        let graphviz = graphviz[0][0]
                            .coerce_to(&DfType::Text(Collation::Utf8), &DfType::Unknown)?;
                        info!(graphviz = %graphviz.as_str().unwrap());
                    }
                }
            }
        }
        Ok(())
    }

    async fn run_statement(
        &self,
        stmt: &Statement,
        conn: &mut DatabaseConnection,
    ) -> anyhow::Result<()> {
        let res = conn.query_drop(&stmt.command).await;
        match stmt.result {
            StatementResult::Ok => {
                if let Err(e) = res {
                    bail!("Statement failed: {}", e);
                }
            }
            StatementResult::Error { ref pattern } => match res {
                Err(e) => {
                    if let Some(pattern) = pattern {
                        if !pattern.is_empty() && !e.to_string().contains(pattern) {
                            bail!("Statement failed with unexpected error: {} (expected to match: {})", e, pattern);
                        }
                    }
                }
                Ok(_) => bail!("Statement should have failed, but succeeded"),
            },
        }
        Ok(())
    }

    async fn run_query(
        &self,
        query: &Query,
        conn: &mut DatabaseConnection,
        is_readyset: bool,
    ) -> anyhow::Result<()> {
        // If this is readyset, drop proxied queries, so that if we are retrying a SELECT and it was
        // previously unsupported (e.g. because a required table hadn't yet been replicated), we
        // will retry caching it instead of assuming it still can't be cached and just proxying it.
        //
        // TODO(REA-4799): remove this once the server tells the adapter about DDL and it
        // invalidates proxied queries
        if is_readyset {
            conn.query_drop("DROP ALL PROXIED QUERIES").await?;
        }

        let results = if query.params.is_empty() {
            conn.query(&query.query).await?
        } else {
            // We manually prepare and drop the statement, so that we can retry caching it if it was
            // previously unsupported.
            let stmt = conn.prepare(&query.query).await?;
            let results = conn.execute(&stmt, query.params.clone()).await?;
            conn.drop_prepared(stmt).await?;
            results
        };

        let mut rows = <Vec<Vec<Value>>>::try_from(results)?.into_iter().map(
            |mut row: Vec<Value>| -> anyhow::Result<Vec<Value>> {
                if let Some(column_types) = &query.column_types {
                    let row_len = row.len();
                    let wrong_columns = || {
                        anyhow!(
                            "Row had the wrong number of columns: expected {}, but got {}",
                            column_types.len(),
                            row_len
                        )
                    };

                    if row.len() > column_types.len() {
                        return Err(wrong_columns());
                    }

                    let mut vals = mem::take(&mut row).into_iter();
                    row = column_types
                        .iter()
                        .map(move |col_type| -> anyhow::Result<Value> {
                            let val = vals.next().ok_or_else(wrong_columns)?;
                            Ok(val
                                .convert_type(col_type)
                                .with_context(|| {
                                    format!("Converting value {val:?} to {col_type:?}")
                                })?
                                .into_owned())
                        })
                        .collect::<Result<_, _>>()?;
                }
                Ok(row)
            },
        );

        let vals: Vec<Value> = match query.sort_mode.unwrap_or_default() {
            SortMode::NoSort => rows.fold_ok(vec![], |mut acc, row| {
                acc.extend(row);
                acc
            })?,
            SortMode::RowSort => {
                let mut rows: Vec<_> = rows.try_collect()?;
                rows.sort();
                rows.into_iter().flatten().collect()
            }
            SortMode::ValueSort => {
                let mut vals = rows.fold_ok(vec![], |mut acc, row| {
                    acc.extend(row);
                    acc
                })?;
                vals.sort();
                vals
            }
        };

        match &query.results {
            QueryResults::Hash { count, digest } => {
                if *count != vals.len() {
                    bail!(
                        "Wrong number of results returned: expected {}, but got {}",
                        count,
                        vals.len(),
                    );
                }
                let actual_digest = Value::hash_results(&vals);
                if actual_digest != *digest {
                    bail!(
                        "Incorrect values returned from query, expected values hashing to {:x}, but got {:x}",
                        digest,
                        actual_digest
                    );
                }
            }
            QueryResults::Results(expected_vals) => {
                if vals.len() != expected_vals.len() {
                    bail!("The number of values returned does not match the number of values expected (left: expected, right: actual): \n {}, {}",expected_vals.len(), vals.len());
                }
                if !compare_results(&vals, expected_vals, query.column_types.is_some()) {
                    bail!(
                        "Incorrect values returned from query (left: expected, right: actual): \n{}",
                        pretty_assertions::Comparison::new(expected_vals, &vals)
                    )
                }
            }
        }

        // If we are running against a remote readyset which could proxy, verify it didn't.
        if is_readyset {
            let explain_results = conn.simple_query("EXPLAIN LAST STATEMENT").await?;
            let explain_values: Vec<Vec<DfValue>> = explain_results.try_into()?;
            if let Some(explain) = explain_values.first() {
                if let Some(destination) = explain.first() {
                    let destination =
                        destination.coerce_to(&DfType::Text(Collation::Utf8), &DfType::Unknown)?;
                    let destination = destination.as_str().unwrap();
                    if destination != "readyset" {
                        bail!("Query destination should be readyset, was {destination}");
                    }
                }
            }
        }

        Ok(())
    }

    async fn start_noria_server(
        &self,
        run_opts: &RunOptions,
        authority: Arc<readyset_server::Authority>,
    ) -> (readyset_server::Handle, ShutdownSender) {
        let mut retry: usize = 0;
        loop {
            retry += 1;

            let mut builder = Builder::for_tests();
            builder.set_mixed_comparisons(true);
            builder.set_straddled_joins(true);
            builder.set_post_lookup(true);
            builder.set_topk(true);
            builder.set_parsing_preset(run_opts.parsing_preset);
            builder.set_dialect(run_opts.database_type.into());

            if run_opts.enable_reuse {
                builder.set_reuse(Some(ReuseConfigType::Finkelstein))
            }

            if let Some(replication_url) = &run_opts.replication_url {
                builder.set_cdc_db_url(replication_url);
                builder.set_upstream_db_url(replication_url);
            }

            let persistence = readyset_server::PersistenceParameters {
                mode: readyset_server::DurabilityMode::DeleteOnExit,
                ..Default::default()
            };

            builder.set_persistence(persistence);

            let (mut noria, shutdown_tx) = match builder.start(Arc::clone(&authority)).await {
                Ok(builder) => builder,
                Err(err) => {
                    // This can error out if there are too many open files, but if we wait a bit
                    // they will get closed (macOS problem)
                    if retry > 100 {
                        panic!("{err:?}")
                    }
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    continue;
                }
            };
            noria.backend_ready().await;
            return (noria, shutdown_tx);
        }
    }

    async fn setup_adapter(
        &self,
        run_opts: &RunOptions,
        authority: Arc<readyset_server::Authority>,
    ) -> (tokio::task::JoinHandle<()>, DatabaseURL) {
        let database_type = run_opts.database_type;
        let replication_url = run_opts.replication_url.clone();
        let auto_increments: Arc<RwLock<HashMap<Relation, AtomicUsize>>> = Arc::default();
        let view_name_cache = SharedCache::new();
        let view_cache = SharedCache::new();
        let mut retry: usize = 0;
        let listener = loop {
            retry += 1;
            match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => break listener,
                Err(err) => {
                    if retry > 100 {
                        panic!("{err:?}")
                    }
                    tokio::time::sleep(Duration::from_millis(1000)).await
                }
            }
        };
        let addr = listener.local_addr().unwrap();

        let mut rh = ReadySetHandle::new(authority.clone()).await;

        let adapter_rewrite_params = rh.adapter_rewrite_params().await.unwrap();
        let adapter_start_time = SystemTime::now();
        let parsing_preset = run_opts.parsing_preset;

        let task = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();

            let noria = NoriaConnector::new(
                rh.clone(),
                auto_increments,
                view_name_cache.new_local(),
                view_cache.new_local(),
                ReadBehavior::Blocking,
                match database_type {
                    DatabaseType::MySQL => readyset_data::Dialect::DEFAULT_MYSQL,
                    DatabaseType::PostgreSQL => readyset_data::Dialect::DEFAULT_POSTGRESQL,
                },
                match database_type {
                    DatabaseType::MySQL => readyset_sql::Dialect::MySQL,
                    DatabaseType::PostgreSQL => readyset_sql::Dialect::PostgreSQL,
                },
                match database_type {
                    DatabaseType::MySQL if replication_url.is_some() => vec!["noria".into()],
                    DatabaseType::PostgreSQL if replication_url.is_some() => {
                        vec!["noria".into(), "public".into()]
                    }
                    _ => Default::default(),
                },
                adapter_rewrite_params,
            )
            .await;
            let query_status_cache: &'static _ = Box::leak(Box::new(QueryStatusCache::new()));

            macro_rules! make_backend {
                ($upstream:ty, $handler:ty, $dialect:expr $(,)?) => {{
                    // cannot use .await inside map
                    #[allow(clippy::manual_map)]
                    let upstream = match &replication_url {
                        Some(url) => Some(
                            <LazyUpstream<$upstream> as UpstreamDatabase>::connect(
                                UpstreamConfig::from_url(url),
                                None,
                                None,
                            )
                            .await
                            .unwrap(),
                        ),
                        None => None,
                    };

                    let status_reporter = ReadySetStatusReporter::new(
                        replication_url
                            .map(UpstreamConfig::from_url)
                            .unwrap_or_default(),
                        Some(rh),
                        Default::default(),
                        authority.clone(),
                        Vec::new(),
                    );
                    BackendBuilder::new()
                        .require_authentication(false)
                        .dialect($dialect)
                        .parsing_preset(parsing_preset)
                        .build::<_, $handler>(
                            noria,
                            upstream,
                            query_status_cache,
                            authority,
                            status_reporter,
                            adapter_start_time,
                        )
                }};
            }

            match database_type {
                DatabaseType::MySQL => MySqlIntermediary::run_on_tcp(
                    readyset_mysql::Backend {
                        noria: make_backend!(MySqlUpstream, MySqlQueryHandler, Dialect::MySQL,),
                        enable_statement_logging: false,
                    },
                    s,
                    false,
                    None,
                    TlsMode::Optional,
                )
                .await
                .unwrap(),
                DatabaseType::PostgreSQL => {
                    psql_srv::run_backend(
                        readyset_psql::Backend::new(make_backend!(
                            PostgreSqlUpstream,
                            PostgreSqlQueryHandler,
                            Dialect::PostgreSQL,
                        )),
                        s,
                        false,
                        None,
                        TlsMode::Optional,
                    )
                    .await
                }
            }
        });

        (
            task,
            match database_type {
                DatabaseType::MySQL => mysql::OptsBuilder::default()
                    .tcp_port(addr.port())
                    .prefer_socket(false)
                    .into(),
                DatabaseType::PostgreSQL => {
                    let mut config = pgsql::Config::default();
                    config.host("localhost");
                    config.port(addr.port());
                    config.dbname("noria");
                    config.into()
                }
            },
        )
    }

    /// Get a reference to the test script's records.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
}
