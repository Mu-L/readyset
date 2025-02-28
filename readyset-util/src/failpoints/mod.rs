//! Failpoints
//!
//! A collection of failpoints that can be enabled if the `failure_injection` feature is set.
//!
//! See **[Failure Injection](../docs/src/failure_injection.md)** for much more details.

/// All requests to the authority will behave as if the Authority is down
///
/// Currently only supports consul.
pub const AUTHORITY: &str = "authority";
/// Injects an error in crate::worker::readers::listen()
pub const READ_QUERY: &str = "read-query";
/// Imitates traffic being dropped from upstream
pub const UPSTREAM: &str = "upstream";
/// Imitates a failure during the `handle_action` in replication
pub const REPLICATION_HANDLE_ACTION: &str = "replication-handle-action";
/// Imitates a failure during `PostgresWalConnector::next_action` in replication
pub const POSTGRES_REPLICATION_NEXT_ACTION: &str = "postgres-replication-next-action";
/// Imitates a failure right before we begin snapshotting against a Postgres upstream
pub const POSTGRES_SNAPSHOT_START: &str = "postgres-snapshot-start";
/// Imitates a failure encountered while performing a full resnapshot
pub const POSTGRES_FULL_RESNAPSHOT: &str = "postgres-full-resnapshot";
/// Imitates a failure encountered while performing a partial resnapshot
pub const POSTGRES_PARTIAL_RESNAPSHOT: &str = "postgres-partial-resnapshot";
/// Imitates a failure encountered while snapshotting a table
pub const POSTGRES_SNAPSHOT_TABLE: &str = "postgres-snapshot-table";
/// Imitates a failure right before we invoke `START_REPLICATION` during Postgres replication
pub const POSTGRES_START_REPLICATION: &str = "postgres-start-replication";
/// Imitates a failure when we go to pull the next event from the WAL during Postgres replication
pub const POSTGRES_NEXT_WAL_EVENT: &str = "postgres-next-wal-event";
/// Imitates a failure in the `NoriaAdapter::start_inner_postgres()` function that happens before we
/// interact with the upstream database
pub const START_INNER_POSTGRES: &str = "start-inner-postgres";
/// Imitate a backwards incompatible deserialization from controller state
pub const LOAD_CONTROLLER_STATE: &str = "load-controller-state";
/// Injects a failpoint at the beginning of DfState::extend_recipe
pub const EXTEND_RECIPE: &str = "extend-recipe";
/// A failpoint at the beginning of the controller's request handling
pub const CONTROLLER_REQUEST: &str = "controller-request";
/// A failpoint at the beginning of the domain's packet handling
pub const HANDLE_PACKET: &str = "handle-packet";
/// A failpoint at the beginning of the reader's packet handling
pub const READER_HANDLE_PACKET: &str = "reader-handle-packet";
/// A failpoint at the beginning of starting the controller
pub const START_CONTROLLER: &str = "start-controller";
/// A failpoint at the beginning of starting the worker
pub const START_WORKER: &str = "start-worker";
/// A failpoint at the beginning of the adapter's out-of-band migration handling
pub const ADAPTER_OUT_OF_BAND: &str = "adapter-out-of-band";
/// A failpoint at the beginning of nom-sql's type identifier parsing
pub const PARSE_SQL_TYPE: &str = "parse-sql-type";
/// A failpoint just before dropping tables due to replication errors
pub const IGNORE_TABLE_FAIL_DROPPING_TABLE: &str = "ignore-table-fail-dropping-table";
/// A failpoint just before waiting on a blocking read in the reader
pub const READER_BEFORE_BLOCKING: &str = "reader-before-blocking";
/// A failpoint at the beginning of handling a RequestReaderReplay packet
pub const UPQUERY_START: &str = "upquery-start";
