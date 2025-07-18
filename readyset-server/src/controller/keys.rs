use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::mem;

pub use common::IndexRef;
use dataflow::prelude::*;
use readyset_errors::ReadySetError;
use vec1::{vec1, Vec1};

// TODO: rewrite as iterator
/// *DEPRECATED*: trace the provenance of the given set ofa columns from the given node up the
/// graph.
///
/// Returns segments in *trace order*, with the target node first and the source node last
pub fn provenance_of(
    graph: &Graph,
    node: NodeIndex,
    columns: &[usize],
) -> Result<Vec<Vec<(NodeIndex, Vec<Option<usize>>)>>, ReadySetError> {
    let path = vec![(node, columns.iter().map(|&v| Some(v)).collect())];
    trace(graph, path)
}

/// The return value of `deduce_column_source`.
#[derive(Debug)]
struct DeducedColumnSource {
    /// Node ancestors to continue building replay paths through. Empty if the node is a base node.
    ancestors: Vec<IndexRef>,
    /// Whether or not the replay path should be broken at the node passed to
    /// `deduced_column_source`.
    ///
    /// When columns are generated, we terminate the current replay path at
    /// the node generating the columns, and start a new replay path from that
    /// node to the node(s) referenced by the node's `column_source` implementation.
    break_path: bool,
}

/// Find the ancestors of the node provided for the given column index (if present), and also
/// check whether the current replay path should be broken at this node.
///
/// (see the `DeducedColumnSource` documentation for more)
fn deduce_column_source(
    graph: &Graph,
    &IndexRef { node, ref index }: &IndexRef,
) -> ReadySetResult<DeducedColumnSource> {
    let parents: Vec<_> = graph
        .neighbors_directed(node, petgraph::EdgeDirection::Incoming)
        .collect();

    if parents.is_empty() {
        // stop here
        return Ok(DeducedColumnSource {
            ancestors: vec![],
            break_path: false,
        });
    }

    let n = &graph[node];

    if !n.is_internal() {
        // we know all non-internal nodes use an identity mapping
        let parent = parents[0];
        return Ok(DeducedColumnSource {
            ancestors: vec![IndexRef {
                node: parent,
                index: index.clone(),
            }],
            break_path: false,
        });
    }

    let colsrc = if let Some(ref index) = *index {
        n.column_source(&index.columns)
    } else {
        // if we don't have any columns to pass to `column_source`, we're going for
        // a full materialization.

        if let Some(mra) = n.must_replay_among() {
            // nodes can specify that they only want replays from some of their parents in
            // the full materialization case. a good example of this is the left join.
            ColumnSource::RequiresFullReplay(
                Vec1::try_from(mra.into_iter().collect::<Vec<_>>()).unwrap(),
            )
        } else {
            // otherwise, we just replay through ALL of the node's parents.

            // unwrap: always succeeds since we checked `parents.is_empty` earlier
            ColumnSource::RequiresFullReplay(Vec1::try_from(parents).unwrap())
        }
    };

    Ok(match colsrc {
        ColumnSource::ExactCopy(ColumnRef { node, columns }) => DeducedColumnSource {
            ancestors: vec![IndexRef::partial(
                node,
                #[allow(clippy::unwrap_used)] // we only hit ExactCopy if we have a partial index
                Index::new(index.as_ref().unwrap().index_type, columns.to_vec()),
            )],
            break_path: false,
        },
        ColumnSource::Union(refs) => DeducedColumnSource {
            ancestors: refs
                .into_iter()
                .map(|ColumnRef { node, columns }| {
                    IndexRef::partial(
                        node,
                        #[allow(clippy::unwrap_used)]
                        // we only hit Union if we have a partial index
                        Index::new(index.as_ref().unwrap().index_type, columns.to_vec()),
                    )
                })
                .collect(),
            break_path: false,
        },
        ColumnSource::GeneratedFromColumns(refs) => DeducedColumnSource {
            ancestors: refs
                .into_iter()
                .map(|ColumnRef { node, columns }| {
                    IndexRef::partial(
                        node,
                        #[allow(clippy::unwrap_used)]
                        // we only hit GeneratedFromColumns if we have a partial index
                        Index::new(index.as_ref().unwrap().index_type, columns.to_vec()),
                    )
                })
                .collect(),
            break_path: true,
        },
        ColumnSource::RequiresFullReplay(nodes) => DeducedColumnSource {
            ancestors: nodes.into_iter().map(|n| IndexRef::full(n)).collect(),
            break_path: false,
        },
    })
}

/// Raw information about a *single* replay path for a particular key.
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct RawReplayPath {
    /// The actual segments of the replay path, listed in *replay* order (with the source of the
    /// key first, and the target of the replay last)
    segments: Vec1<IndexRef>,
    /// The index in `segments` that is the *target* of the replay path. Usually just the last
    /// segment, except in the case of extended replay paths
    ///
    /// Invariant: This will always be valid index in `self.segments`
    target_index: usize,
    /// Was this path "broken off" at a set of generated columns?
    broken: bool,
}

impl RawReplayPath {
    /// Create a new *unbroken* [`RawReplayPath`] from the given list of segments, listed in replay
    /// order (with the source of the key first, and the target of the replay last)
    pub fn from_replay(segments: Vec1<IndexRef>) -> Self {
        debug_assert!(
            {
                let mut uniq = HashSet::new();
                segments.iter().all(|ir| uniq.insert(ir.node))
            },
            "Tried to construct cyclic RawReplayPath: {segments:?}"
        );
        Self {
            target_index: segments.len() - 1,
            segments,
            broken: false,
        }
    }

    /// Create a new *unbroken* [`RawReplayPath`] from the given list of segments, listed in *trace*
    /// order (with the target of the replay first, and the source of the key last)
    pub fn from_trace(mut trace: Vec1<IndexRef>) -> Self {
        trace.reverse();
        Self::from_replay(trace)
    }

    /// Create a new *broken* [`RawReplayPath`] from the given list of segments, listed in *trace*
    /// order (with the target of the replay first, and the source of the key last)
    ///
    /// A "broken" replay path is one that terminates at a set of columns that is generated from a
    /// node, rather than a materialization that is directly able to satisfy lookups for the replay
    pub fn from_broken_trace(trace: Vec1<IndexRef>) -> Self {
        Self {
            broken: true,
            ..Self::from_trace(trace)
        }
    }

    /// Returns the number of segments in this replay path, excluding any extensions
    pub fn len(&self) -> usize {
        self.target_index + 1
    }

    /// Returns the number of segments in this replay path, including any extensions
    ///
    /// See [the docs section on straddled joins][straddled-joins] for more information about
    /// extended replay paths
    ///
    /// [straddled-joins]: http://docs/dataflow/replay_paths.html#straddled-joins
    pub fn len_with_extension(&self) -> usize {
        self.segments.len()
    }

    /// Add an *extension* to this replay path, leaving the last segment as the target.
    ///
    /// See [the docs section on straddled joins][straddled-joins] for more information about
    /// extended replay paths
    ///
    /// [straddled-joins]: http://docs/dataflow/replay_paths.html#straddled-joins
    #[must_use]
    pub fn with_extension<I>(mut self, extension: I) -> Self
    where
        I: IntoIterator<Item = IndexRef>,
    {
        self.segments.extend(extension);
        self
    }

    /// Returns the [`IndexRef`] at the source of this replay path (where the columns come from)
    pub fn source(&self) -> &IndexRef {
        &self.segments[0]
    }

    /// Returns the [`IndexRef`] at the target of this replay path
    pub fn target(&self) -> &IndexRef {
        &self.segments[self.target_index]
    }

    pub fn last_segment(&self) -> &IndexRef {
        self.segments.last()
    }

    /// Returns a slice of the actual segments in this replay path, excluding any extensions
    pub fn segments(&self) -> &[IndexRef] {
        &self.segments[..=self.target_index]
    }

    /// Returns a slice of the actual segments in this replay path, including any extensions
    ///
    /// See [the docs section on straddled joins][straddled-joins] for more information about
    /// extended replay paths
    ///
    /// [straddled-joins]: http://docs/dataflow/replay_paths.html#straddled-joins
    pub fn segments_with_extension(&self) -> &[IndexRef] {
        &self.segments
    }

    /// If this replay path has an extension, return the segments of that extension, otherwise
    /// return `None`
    ///
    /// See [the docs section on straddled joins][straddled-joins] for more information about
    /// extended replay paths
    ///
    /// [straddled-joins]: http://docs/dataflow/replay_paths.html#straddled-joins
    pub fn extension(&self) -> Option<&[IndexRef]> {
        if self.len() == self.len_with_extension() {
            None
        } else {
            Some(&self.segments()[(self.target_index + 1)..])
        }
    }

    /// Does this replay path have an extension?
    ///
    /// See [the docs section on straddled joins][straddled-joins] for more information about
    /// extended replay paths
    ///
    /// [straddled-joins]: http://docs/dataflow/replay_paths.html#straddled-joins
    pub fn has_extension(&self) -> bool {
        self.extension().is_some()
    }

    /// Was this replay path "broken off" at a set of columns that is generated from a node?
    pub fn broken(&self) -> bool {
        self.broken
    }

    /// Returns the index within [`self.segments_with_extension()`][segments_with_extension] of the
    /// *target* of this replay path.
    ///
    /// [segments]: RawReplayPath::segment_with_extensions
    pub fn target_index(&self) -> usize {
        self.target_index
    }
}

/// Construct a replay path starting at the trace of columns given by `current`.
///
/// `current` should be a path specified in *trace order* (from destination to source), but this
/// function will return paths in *replay order* (from source to destination)
///
/// In the simplest case (i.e. a straight line from base table to source node, with no branching or
/// nodes with multiple ancestors), this will just add the next ancestor to `current`, recursively
/// call itself, and then return `vec![current]` when it gets to the base table.
///
/// In cases where the current node has multiple ancestors, this recursively calls itself *for each
/// ancestor*, and then returns a vector of all of the replay paths generated by doing so.
///
/// If this function encounters an index *during execution* that contains generated columns, it will
/// stop, and all the resulting replay paths will have [`broken`](RawReplayPath::broken) set to
/// `true`. On the other hand, if this function *starts* at a set of generated columns, it will do
/// one of two things:
///
/// - If that set of generated columns is generated from a different set of columns *in the same
///   node*, the resulting replay path will instead terminate *at the columns that are generated
///   from*
/// - If that set of generated columns is generated from a *parent* node, this function will return
///   an *extended* replay path. See [the docs section on straddled joins][straddled-joins] for more
///   information about extended replay paths
///
/// [straddled-joins]: http://docs/dataflow/replay_paths.html#straddled-joins
fn continue_replay_path<F>(
    graph: &Graph,
    mut current: Vec1<IndexRef>,
    stop_at: &F,
) -> ReadySetResult<Vec<RawReplayPath>>
where
    F: Fn(NodeIndex) -> bool,
{
    let current_colref = current.last().clone();

    if stop_at(current_colref.node) || graph[current_colref.node].is_base() {
        // do not continue resolving past the current node
        return Ok(vec![RawReplayPath::from_trace(current)]);
    }

    let dcs = deduce_column_source(graph, &current_colref)?;

    match dcs.ancestors.len() {
        // stop and return the current replay path in full
        0 => Ok(vec![RawReplayPath::from_trace(current)]),
        1 => {
            // only one ancestor, and its column reference is:
            let next_colref = dcs.ancestors.into_iter().next().unwrap();
            // don't break the path if we're only a 1-node replay path
            if dcs.break_path && current.len() > 1 {
                Ok(vec![RawReplayPath::from_broken_trace(current)])
            } else {
                let extension = if current_colref.node == next_colref.node {
                    // note: [generated-from-self]
                    // The ingredient has indicated that this set of columns (at the start of a
                    // path, since we just checked the len() is 1 above) is generated from a
                    // different set of columns *in the same node*. That means we want the replay
                    // path to target *that* set of columns (`next_colref`, here), instead of the
                    // remapped columns.
                    *current.last_mut() = next_colref;
                    None
                } else if dcs.break_path {
                    // If we're generating columns from a parent, then the path we've already got is
                    // an extension
                    let mut ext = mem::replace(&mut current, vec1![next_colref]);
                    ext.reverse(); // trace order -> replay order
                    Some(ext)
                } else {
                    current.push(next_colref);
                    None
                };

                let paths = continue_replay_path(graph, current, stop_at)?;
                if let Some(extension) = extension {
                    Ok(paths
                        .into_iter()
                        .map(|p| p.with_extension(extension.clone()))
                        .collect())
                } else {
                    Ok(paths)
                }
            }
        }
        _ => {
            // multiple ancestors
            if dcs.break_path && current.len() > 1 {
                Ok(vec![RawReplayPath::from_broken_trace(current)])
            } else {
                let mut ret = vec![];
                for next_colref in dcs.ancestors {
                    let mut next = current.clone();
                    let extension = if current_colref.node == next_colref.node {
                        // see note: [generated-from-self]
                        *next.last_mut() = next_colref;
                        None
                    } else if dcs.break_path {
                        // If we're generating columns from a parent, then the path we've already
                        // got is an extension
                        let mut ext = mem::replace(&mut next, vec1![next_colref]);
                        ext.reverse();
                        Some(ext)
                    } else {
                        next.push(next_colref);
                        None
                    };

                    let paths = continue_replay_path(graph, next, stop_at)?;
                    if let Some(extension) = extension {
                        ret.extend(
                            paths
                                .into_iter()
                                .map(|p| p.with_extension(extension.clone())),
                        )
                    } else {
                        ret.extend(paths)
                    }
                }
                Ok(ret)
            }
        }
    }
}

/// Given a `ColumnRef`, and an `IndexType`, generate all replay paths needed to generate a
/// **partial** materialization for those columns on that node, if one is possible.
///
/// If a partial materialization is not desired, use the `replay_paths_for_opt` API instead, which
/// will not try and handle generated columns.
///
/// If `stop_at` is provided, replay paths will not continue past (but will include) nodes for which
/// `stop_at(node_index)` returns `true`. (The intended usage here is for `stop_at` to return
/// `true` for nodes that already have a materialization.)
///
/// Note that this function returns replay paths in *replay order*, with the source node first and
/// the target node last
pub fn replay_paths_for<F>(
    graph: &Graph,
    ColumnRef { node, columns }: ColumnRef,
    index_type: IndexType,
    stop_at: F,
) -> ReadySetResult<Vec<RawReplayPath>>
where
    F: Fn(NodeIndex) -> bool,
{
    replay_paths_for_opt(
        graph,
        IndexRef::partial(node, Index::new(index_type, columns.to_vec())),
        stop_at,
    )
}

/// Like `replay_paths_for`, but allows specifying an `IndexRef` instead of a `ColumnRef`.
///
/// This is useful for full materialization cases where specifying a `ColumnRef` will try and
/// generate split replay paths for generated columns, which is highly undesirable unless we're
/// doing partial.
///
/// Note that this function returns replay paths in *replay order*, with the source node first and
/// the target node last
pub fn replay_paths_for_opt<F>(
    graph: &Graph,
    colref: IndexRef,
    stop_at: F,
) -> ReadySetResult<Vec<RawReplayPath>>
where
    F: Fn(NodeIndex) -> bool,
{
    continue_replay_path(graph, vec1![colref], &stop_at)
}

/// Like `replay_paths_for`, but `stop_at` always returns `false`.
///
/// Note that this function returns replay paths in *replay order*, with the source node first and
/// the target node last
pub fn replay_paths_for_nonstop(
    graph: &Graph,
    colref: ColumnRef,
    index_type: IndexType,
) -> ReadySetResult<Vec<RawReplayPath>> {
    let never_stop = |_| false;
    replay_paths_for(graph, colref, index_type, never_stop)
}

fn trace(
    graph: &Graph,
    mut path: Vec<(NodeIndex, Vec<Option<usize>>)>,
) -> ReadySetResult<Vec<Vec<(NodeIndex, Vec<Option<usize>>)>>> {
    // figure out what node/column we're looking up
    let (node, columns) = path.last().cloned().unwrap();
    let cols = columns.len();

    let parents: Vec<_> = graph
        .neighbors_directed(node, petgraph::EdgeDirection::Incoming)
        .collect();

    if parents.is_empty() {
        // this path reached the source node.
        // but we should have stopped at base nodes above...
        internal!("considering a node with no parents");
    }

    let n = &graph[node];

    // have we reached a base node?
    if n.is_base() {
        return Ok(vec![path]);
    }

    // we know all non-internal nodes use an identity mapping
    if !n.is_internal() {
        let parent = parents[0];
        path.push((parent, columns));
        return trace(graph, path);
    }

    // if all our inputs are None, our job is trivial
    // we just go trace back to all ancestors
    if columns.iter().all(Option::is_none) {
        // except if must_replay_among is defined, in which case we replay through the set
        // provided in that API
        if let Some(mra) = n.must_replay_among() {
            let mut paths = Vec::with_capacity(mra.len());
            for p in mra {
                let mut path = path.clone();
                path.push((p, vec![None; cols]));
                paths.extend(trace(graph, path)?);
            }
            return Ok(paths);
        }

        let mut paths = Vec::with_capacity(parents.len());
        for p in parents {
            let mut path = path.clone();
            path.push((p, vec![None; cols]));
            paths.extend(trace(graph, path)?);
        }
        return Ok(paths);
    }

    // try to resolve the currently selected columns
    let mut resolved = columns
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| c.map(|c| (i, c)))
        .map(|(i, c)| Ok((i, n.parent_columns(c))))
        .collect::<Result<Vec<(usize, Vec<(NodeIndex, Option<usize>)>)>, ReadySetError>>()?
        .iter()
        .flat_map(|(i, origins)| {
            assert!(!origins.is_empty());
            origins.iter().map(move |o| (i, o))
        })
        .fold(
            HashMap::new(),
            |mut by_ancestor, (coli, (ancestor, column))| {
                {
                    let resolved = by_ancestor
                        .entry(*ancestor)
                        .or_insert_with(|| vec![None; cols]);
                    resolved[*coli] = *column;
                }
                by_ancestor
            },
        );
    assert!(!resolved.is_empty(), "Some(col) resolved into no ancestors");

    // are any of the columns generated?
    if let Some(columns) = resolved.remove(&node) {
        // some are, so at this point we know we'll need to yield None for those columns all the
        // way back to the root of the graph.

        // resolving to Some on self makes no sense...
        assert!(columns.iter().all(Option::is_none));

        if parents.len() != 1 {
            // TODO: we have a join-like thing, so we'd need to call on_join
            // like in the case of all our inputs being None above.
            unimplemented!();
        }

        let mut paths = Vec::with_capacity(parents.len());
        for p in parents {
            let mut path = path.clone();
            path.push((p, resolved.remove(&p).unwrap_or_else(|| vec![None; cols])));
            paths.extend(trace(graph, path)?);
        }
        return Ok(paths);
    }

    // no, it resolves to at least one parent column
    // if there is only one parent, we can step right to that
    if resolved.len() == 1 {
        let (parent, resolved) = resolved.into_iter().next().unwrap();
        path.push((parent, resolved));
        return trace(graph, path);
    }

    // traverse up all the paths
    let mut paths = Vec::with_capacity(parents.len());
    for (parent, columns) in resolved {
        let mut path = path.clone();
        path.push((parent, columns));
        paths.extend(trace(graph, path)?);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use dataflow::utils::make_columns;
    use dataflow::{node, ops, Expr};
    use readyset_data::DfType;
    use readyset_sql::ast::OrderType;

    use super::*;

    fn bases() -> (Graph, NodeIndex, NodeIndex) {
        let mut g = petgraph::Graph::new();
        let src = g.add_node(node::Node::new(
            "source",
            make_columns(&[""]),
            node::special::Source,
        ));

        let a = g.add_node(node::Node::new(
            "a",
            make_columns(&["a1", "a2"]),
            node::special::Base::default(),
        ));
        g.add_edge(src, a, ());

        let b = g.add_node(node::Node::new(
            "b",
            make_columns(&["b1", "b2"]),
            node::special::Base::default(),
        ));
        g.add_edge(src, b, ());

        (g, a, b)
    }

    #[test]
    fn base_trace() {
        let (g, a, b) = bases();
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: a,
                    columns: vec![0]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![IndexRef::partial(
                a,
                Index::hash_map(vec![0])
            )])]
        );
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: b,
                    columns: vec![0]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![IndexRef::partial(
                b,
                Index::hash_map(vec![0])
            )])]
        );

        // multicol
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: a,
                    columns: vec![0, 1]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![IndexRef::partial(
                a,
                Index::hash_map(vec![0, 1])
            )])]
        );

        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: a,
                    columns: vec![1, 0]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![IndexRef::partial(
                a,
                Index::hash_map(vec![1, 0])
            )])]
        );
    }

    #[test]
    fn internal_passthrough() {
        let (mut g, a, _) = bases();

        let x = g.add_node(node::Node::new(
            "x",
            make_columns(&["x1", "x2"]),
            node::special::Ingress,
        ));
        g.add_edge(a, x, ());

        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![0]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![0])),
                IndexRef::partial(x, Index::hash_map(vec![0])),
            ])]
        );

        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![0, 1]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![0, 1])),
                IndexRef::partial(x, Index::hash_map(vec![0, 1])),
            ])]
        );
    }

    #[test]
    fn col_reorder() {
        let (mut g, a, _) = bases();

        let x = g.add_node(node::Node::new(
            "x",
            make_columns(&["x2", "x1"]),
            ops::NodeOperator::Project(ops::project::Project::new(
                a,
                vec![
                    Expr::Column {
                        index: 1,
                        ty: DfType::Unknown,
                    },
                    Expr::Column {
                        index: 0,
                        ty: DfType::Unknown,
                    },
                ],
            )),
        ));
        g.add_edge(a, x, ());

        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![0]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![1])),
                IndexRef::partial(x, Index::hash_map(vec![0])),
            ])]
        );
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![0, 1]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![1, 0])),
                IndexRef::partial(x, Index::hash_map(vec![0, 1])),
            ])]
        );
    }

    #[test]
    fn requires_full_replay() {
        let (mut g, a, _) = bases();

        let x = g.add_node(node::Node::new(
            "x",
            make_columns(&["x1", "foo"]),
            ops::NodeOperator::Project(ops::project::Project::new(
                a,
                vec![
                    Expr::Column {
                        index: 0,
                        ty: DfType::Unknown,
                    },
                    Expr::Literal {
                        val: DfValue::from(42),
                        ty: DfType::Int,
                    },
                ],
            )),
        ));
        g.add_edge(a, x, ());

        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![0]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![0])),
                IndexRef::partial(x, Index::hash_map(vec![0])),
            ])]
        );
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![1]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::full(a),
                IndexRef::partial(x, Index::hash_map(vec![1])),
            ])]
        );
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![0, 1]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::full(a),
                IndexRef::partial(x, Index::hash_map(vec![0, 1])),
            ])]
        );
    }

    #[test]
    fn union_straight() {
        let (mut g, a, b) = bases();

        let x = g.add_node(node::Node::new(
            "x",
            make_columns(&["x1", "x2"]),
            ops::NodeOperator::Union(
                ops::union::Union::new(
                    vec![(a, vec![0, 1]), (b, vec![0, 1])].into_iter().collect(),
                    ops::union::DuplicateMode::UnionAll,
                )
                .unwrap(),
            ),
        ));
        g.add_edge(a, x, ());
        g.add_edge(b, x, ());

        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: x,
                columns: vec![0],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![
                RawReplayPath::from_replay(vec1![
                    IndexRef::partial(a, Index::hash_map(vec![0])),
                    IndexRef::partial(x, Index::hash_map(vec![0])),
                ]),
                RawReplayPath::from_replay(vec1![
                    IndexRef::partial(b, Index::hash_map(vec![0])),
                    IndexRef::partial(x, Index::hash_map(vec![0])),
                ]),
            ]
        );

        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: x,
                columns: vec![0, 1],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![
                RawReplayPath::from_replay(vec1![
                    IndexRef::partial(a, Index::hash_map(vec![0, 1])),
                    IndexRef::partial(x, Index::hash_map(vec![0, 1])),
                ]),
                RawReplayPath::from_replay(vec1![
                    IndexRef::partial(b, Index::hash_map(vec![0, 1])),
                    IndexRef::partial(x, Index::hash_map(vec![0, 1])),
                ]),
            ]
        );
    }

    #[test]
    fn inner_join() {
        let (mut g, a, b) = bases();

        let x = g.add_node(node::Node::new(
            "x",
            make_columns(&["a1", "a2b1", "b2"]),
            ops::NodeOperator::Join(ops::join::Join::new(
                a,
                b,
                ops::join::JoinType::Inner,
                vec![(1, 0)],
                vec![
                    (ops::Side::Left, 0),
                    (ops::Side::Left, 1),
                    (ops::Side::Right, 1),
                ],
                true,
            )),
        ));
        g.add_edge(a, x, ());
        g.add_edge(b, x, ());

        // left-only column should replay via the left only
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![0]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![0])),
                IndexRef::partial(x, Index::hash_map(vec![0])),
            ])]
        );

        // right-only column should replay via the right only
        assert_eq!(
            replay_paths_for_nonstop(
                &g,
                ColumnRef {
                    node: x,
                    columns: vec![2]
                },
                IndexType::HashMap
            )
            .unwrap(),
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(b, Index::hash_map(vec![1])),
                IndexRef::partial(x, Index::hash_map(vec![2])),
            ])]
        );

        // middle column is in left node, so will replay from left
        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: x,
                columns: vec![1],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![1])),
                IndexRef::partial(x, Index::hash_map(vec![1])),
            ])]
        );

        // indexing (left, middle) should replay (left, middle) from left
        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: x,
                columns: vec![0, 1],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(a, Index::hash_map(vec![0, 1])),
                IndexRef::partial(x, Index::hash_map(vec![0, 1])),
            ]),]
        );

        // indexing (middle, right) should replay (middle, right) from right
        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: x,
                columns: vec![1, 2],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![RawReplayPath::from_replay(vec1![
                IndexRef::partial(b, Index::hash_map(vec![0, 1])),
                IndexRef::partial(x, Index::hash_map(vec![1, 2])),
            ]),]
        );
    }

    #[test]
    fn generated_columns_from_parent() {
        let (mut g, a, b) = bases();

        let x = g.add_node(node::Node::new(
            "x",
            make_columns(&["a1", "a2b1", "b2"]),
            ops::NodeOperator::Join(ops::join::Join::new(
                a,
                b,
                ops::join::JoinType::Inner,
                vec![(1, 0)],
                vec![
                    (ops::Side::Left, 0),
                    (ops::Side::Left, 1),
                    (ops::Side::Right, 1),
                ],
                true,
            )),
        ));
        g.add_edge(a, x, ());
        g.add_edge(b, x, ());

        let reader = g.add_node(node::Node::new(
            "reader",
            make_columns(&["a1", "a2b1", "b2"]),
            node::special::Reader::new(x, Default::default())
                .with_index(&Index::hash_map(vec![0, 2])),
        ));
        g.add_edge(x, reader, ());

        // indexing (left, middle, right) should replay (left, middle) from left and (right) from
        // right
        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: x,
                columns: vec![0, 1, 2],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![
                RawReplayPath::from_replay(vec1![IndexRef::partial(
                    a,
                    Index::hash_map(vec![0, 1])
                )])
                .with_extension(vec![IndexRef::partial(x, Index::hash_map(vec![0, 1, 2]))]),
                RawReplayPath::from_replay(vec1![IndexRef::partial(
                    b,
                    Index::hash_map(vec![0, 1])
                ),])
                .with_extension(vec![IndexRef::partial(x, Index::hash_map(vec![0, 1, 2]))]),
            ]
        );

        // indexing (left, right) should replay (left) from left and (right) from right
        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: x,
                columns: vec![0, 2],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec![
                RawReplayPath::from_replay(vec1![IndexRef::partial(a, Index::hash_map(vec![0])),])
                    .with_extension(vec![IndexRef::partial(x, Index::hash_map(vec![0, 2]))]),
                RawReplayPath::from_replay(vec1![IndexRef::partial(
                    b,
                    Index::hash_map(vec![0, 1])
                ),])
                .with_extension(vec![IndexRef::partial(x, Index::hash_map(vec![0, 2]))]),
            ]
        );

        let reader_paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: reader,
                columns: vec![0, 2],
            },
            IndexType::HashMap,
        )
        .unwrap();

        assert_eq!(reader_paths.len(), 1);
        assert!(reader_paths[0].broken);
        assert_eq!(
            reader_paths[0].segments(),
            &[
                IndexRef::partial(x, Index::hash_map(vec![0, 2])),
                IndexRef::partial(reader, Index::hash_map(vec![0, 2])),
            ]
        );
    }

    #[test]
    fn generated_columns_from_self() {
        let (mut g, a, _) = bases();
        eprintln!("base: {a:?}");

        let mut paginate_node = node::Node::new(
            "paginate",
            make_columns(&["a1", "a2", "__page_number"]),
            ops::NodeOperator::Paginate(ops::paginate::Paginate::new(
                a,
                vec![(0, OrderType::OrderAscending)],
                vec![1],
                3,
            )),
        );
        paginate_node.on_connected(&g);
        let paginate = g.add_node(paginate_node);
        g.add_edge(a, paginate, ());

        {
            let paginate_ip = IndexPair::from(paginate);
            let paginate_node = g.node_weight_mut(paginate).unwrap();
            paginate_node.set_finalized_addr(paginate_ip);
            paginate_node.on_commit(&HashMap::from([
                (paginate, paginate_ip),
                (a, IndexPair::from(a)),
            ]))
        }
        eprintln!("paginate: {paginate:?}");

        let reader = g.add_node(node::Node::new(
            "reader",
            make_columns(&["a1", "a2", "__page_number"]),
            node::special::Reader::new(paginate, Default::default())
                .with_index(&Index::hash_map(vec![1, 2])),
        ));
        g.add_edge(paginate, reader, ());
        eprintln!("reader: {reader:?}");

        let mut paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: reader,
                columns: vec![1, 2],
            },
            IndexType::HashMap,
        )
        .unwrap();
        paths.sort_by_key(|p| p.segments()[0].node);

        // A path to the paginate node, that *stops* at the paginate node
        assert_eq!(paths.len(), 1);
        assert!(paths[0].broken());
        assert_eq!(
            paths[0].segments(),
            vec![
                IndexRef::partial(paginate, Index::hash_map(vec![1, 2])),
                IndexRef::partial(reader, Index::hash_map(vec![1, 2])),
            ]
        );

        // Asking for replay paths to the generated columns should generate the paths to the
        // *remapped* columns instead
        let generated_cols_paths = replay_paths_for_nonstop(
            &g,
            ColumnRef {
                node: paginate,
                columns: vec![1, 2],
            },
            IndexType::HashMap,
        )
        .unwrap();
        assert_eq!(generated_cols_paths.len(), 1);
        assert!(!generated_cols_paths[0].broken());
        assert_eq!(
            generated_cols_paths[0].segments(),
            vec![
                IndexRef::partial(a, Index::hash_map(vec![1])),
                IndexRef::partial(paginate, Index::hash_map(vec![1])),
            ]
        );
    }
}
