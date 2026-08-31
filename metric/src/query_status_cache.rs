/// Gauge: The size of the dash map that holds query status of each query that have been processed
/// by readyset adapter.
pub const QUERY_STATUS_CACHE_SIZE: &str = "readyset_query_status_cache.id_to_status.size";

/// Gauge: The size of the LRUCache that holds full query & query status for a fixed number of
/// queries that have been processed by readyset adapter.
pub const QUERY_STATUS_CACHE_PERSISTENT_CACHE_SIZE: &str =
    "readyset_query_status_cache.persistent_cache.statuses.size";

/// Gauge: The size of the query status cache's id-to-status mapping
pub const QUERY_STATUS_CACHE_ID_TO_STATUS_SIZE: &str =
    "readyset_query_status_cache_id_to_status_size";

/// Gauge: The size of the query status cache's statuses collection
pub const QUERY_STATUS_CACHE_STATUSES_SIZE: &str = "readyset_query_status_cache_statuses_size";

/// Gauge: The size of the query status cache's pending inlined migrations
pub const QUERY_STATUS_CACHE_PENDING_INLINE_MIGRATIONS: &str =
    "readyset_query_status_cache_pending_inline_migrations";

/// Counter: Lookups of a cache that keeps its author's literals inline, labelled `result` with
/// `hit` or `miss`. A read whose literals no cache kept is served upstream, so a mode that works
/// and one that never matches look alike without this.
pub const INLINE_LITERAL_CACHE_LOOKUPS: &str = "readyset_inline_literal_cache_lookups";
