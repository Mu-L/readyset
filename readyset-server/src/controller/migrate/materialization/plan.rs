#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable
)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;

use dataflow::payload::{PrepareStateKind, ReplayPathSegment, SourceSelection, TriggerEndpoint};
use dataflow::prelude::*;
use dataflow::DomainRequest;
use readyset_errors::ReadySetError;
use tracing::{debug, trace};
use vec1::Vec1;

use crate::controller::keys::{self, IndexRef, RawReplayPath};
use crate::controller::migrate::DomainMigrationPlan;
use crate::controller::state::Graphviz;

/// A struct representing all the information required to construct and maintain the
/// materializations for a single node within a dataflow graph.
///
/// A [`Plan`] is [constructed] for a single node with references to a dataflow [`Graph`] and the
/// [`Materializations`] in that graph, and over the course of its existence mutates that set of
/// materializations and also adds new messages to a [`DomainMigrationPlan`] to inform domains
/// throughout the graph of information they need to know about maintaining the materializations of
/// that node, including but not limited to:
///
/// - Information about replay paths that originate at the node (both for the domain containing the
///   node, and the domain containing nodes along those replay paths)
/// - Information about [columns that are generated][generated-cols] by the node
/// - Informing [egress nodes][] about tags of their targets
/// - Informing domains about indices they need to create for materializations
///
/// [constructed]: Plan::new
/// [generated-cols]: ColumnSource::GeneratedFromColumns
/// [egress nodes]: dataflow::node::special::Egress
pub(super) struct Plan<'a> {
    /// A reference to the materializations in the graph. Only mutated to generate new [`Tag`]s for
    /// replay paths
    m: &'a mut super::Materializations,
    graph: &'a Graph,
    node: NodeIndex,
    dmp: &'a mut DomainMigrationPlan,
    partial: bool,

    /// Map from indexes we're adding to this node, to the list of tags which identify those
    /// indexes
    indexes: HashMap<Index, Vec<Tag>>,
    /// Indexes in *parent* nodes for extended replay paths we've already added
    ///
    /// Used to prevent adding the same replay path for an extended replay path twice, for example
    /// if two different downstream sets of columns remap to the same set of columns in the parent
    parent_indexes: HashMap<NodeIndex, HashSet<Index>>,
    /// New paths added in this run of the planner.
    paths: HashMap<Tag, (Index, Vec<NodeIndex>)>,
    /// Do we already have some replay paths for this node?
    has_paths: bool,
    pending: Vec<PendingReplay>,
}

#[derive(Debug)]
pub(super) struct PendingReplay {
    pub(super) tag: Tag,
    pub(super) source: LocalNodeIndex,
    pub(super) source_domain: DomainIndex,
    pub(super) target_domain: DomainIndex,

    // If the segment contained a join, we need to ensure any fully materialized
    // nodes in all ancestors are `Ready` before we start the replay. Else on restart, we have a
    // race condition between the replay hitting the join node and doing a lookup on the other
    // parent, and the other parent actually having it's base tables opened.
    pub(super) additional_ancestors: HashSet<(DomainIndex, LocalNodeIndex)>,
}

impl<'a> Plan<'a> {
    pub(super) fn new(
        m: &'a mut super::Materializations,
        graph: &'a Graph,
        node: NodeIndex,
        dmp: &'a mut DomainMigrationPlan,
    ) -> Plan<'a> {
        let partial = m.partial.contains(&node);
        let has_paths = m.paths.get(&node).is_some_and(|paths| !paths.is_empty());
        Plan {
            m,
            graph,
            node,
            dmp,
            partial,

            indexes: Default::default(),
            parent_indexes: Default::default(),
            paths: Default::default(),
            has_paths,
            pending: Vec::new(),
        }
    }

    /// Compute the set of replay paths required to construct and maintain the given `index` in our
    /// node.
    ///
    /// Note that if passed an index for a set of generated columns, this may return paths targeting
    /// a different index than the passed `index`.
    fn paths(&self, index: &Index) -> ReadySetResult<Vec<RawReplayPath>> {
        let graph = self.graph;
        let ni = self.node;
        let mut paths = keys::replay_paths_for_opt(
            graph,
            IndexRef {
                node: ni,
                index: if self.partial {
                    Some(index.clone())
                } else {
                    None
                },
            },
            |stop_ni| {
                stop_ni != ni
                    && self
                        .m
                        .have
                        .get(&stop_ni)
                        .map(|x| !x.is_empty())
                        .unwrap_or(false)
            },
        )?
        .into_iter()
        .collect::<Vec<_>>();

        if !self.m.config.allow_straddled_joins
            && paths.iter().any(|p| {
                // "has extension" is currently a weak-ish proxy for straddled joins, but works
                // since straddled joins are the only case where we make extended replay paths right
                // now
                p.has_extension()
            })
        {
            unsupported!("Straddled joins are not supported");
        }

        // don't include paths that don't end at this node.
        // TODO(aspen): is this necessary anymore? I don't think so
        paths.retain(|x| x.last_segment().node == ni);

        // since we cut off part of each path, we *may* now have multiple paths that are the same
        // (i.e., if there was a union above the nearest materialization). this would be bad, as it
        // would cause a domain to request replays *twice* for a key from one view!
        paths.sort();
        paths.dedup();

        // all columns better resolve if we're doing partial
        if self.partial
            && !paths
                .iter()
                .all(|p| p.segments().iter().all(|cr| cr.index.is_some()))
        {
            internal!("tried to be partial over replay paths that require full materialization: paths = {:?}", paths);
        }

        Ok(paths)
    }

    /// Find the groupings of any unions for the given paths. This optimizes upqueries in queries
    /// that contain complex unions.
    ///
    /// A classical comment follows ...
    ///
    /// all right, story time!
    ///
    /// imagine you have this graph:
    ///
    /// ```text
    ///     a     b
    ///     +--+--+
    ///        |
    ///       u_1
    ///        |
    ///     +--+--+
    ///     c     d
    ///     +--+--+
    ///        |
    ///       u_2
    ///        |
    ///     +--+--+
    ///     e     f
    ///     +--+--+
    ///        |
    ///       u_3
    ///        |
    ///        v
    /// ```
    ///
    /// where c-f are all stateless. you will end up with 8 paths for replays to v.
    /// a and b will both appear as the root of 4 paths, and will be upqueried that many times.
    /// while inefficient (TODO), that is not in and of itself a problem. the issue arises at
    /// the unions, which need to do union buffering (that is, they need to forward _one_
    /// upquery response for each set of upquery responses they get). specifically, u_1 should
    /// forward 4 responses, even though it receives 8. u_2 should forward 2 responses, even
    /// though it gets 4, etc. we may later optimize that (in theory u_1 should be able to only
    /// forward _one_ response to multiple children, and a and b should only be upqueried
    /// _once_), but for now we need to deal with the correctness issue that arises if the
    /// unions do not buffer correctly.
    ///
    /// the issue, ultimately, is what the unions "group" upquery responses by. they can't group
    /// by tag (like shard mergers do), since there are 8 tags here, so there'd be 8 groups each
    /// with one response. here are the replay paths for u_1:
    ///
    ///  1. a -> c -> e
    ///  2. a -> c -> f
    ///  3. a -> d -> e
    ///  4. a -> d -> f
    ///  5. b -> c -> e
    ///  6. b -> c -> f
    ///  7. b -> d -> e
    ///  8. b -> d -> f
    ///
    /// we want to merge 1 with 5 since they're "going the same way". similarly, we want to
    /// merge 2 and 6, 3 and 7, and 4 and 8. the "grouping" here then is really the suffix of
    /// the replay's path beyond the union we're looking at. for u_2:
    ///
    ///  1/5. a/b -> c -> e
    ///  2/6. a/b -> c -> f
    ///  3/7. a/b -> d -> e
    ///  4/8. a/b -> d -> f
    ///
    /// we want to merge 1/5 and 3/7, again since they are going the same way _from here_.
    /// and similarly, we want to merge 2/6 and 4/8.
    ///
    /// so, how do we communicate this grouping to each of the unions?
    /// well, most of the infrastructure is actually already there in the domains.
    /// for each tag, each domain keeps some per-node state (`ReplayPathSegment`).
    /// we can inject the information there!
    ///
    /// we're actually going to play an additional trick here, as it allows us to simplify the
    /// implementation a fair amount. since we know that tags 1 and 5 are identical beyond u_1
    /// (that's what we're grouping by after all!), why don't we just rewrite all 1 tags to 5s?
    /// and all 2s to 6s, and so on. that way, at u_2, there will be no replays with tag 1 or 3,
    /// only 5 and 7. then we can pull the same trick there -- rewrite all 5s to 7s, so that at
    /// u_3 we only need to deal with 7s (and 8s). this simplifies the implementation since
    /// unions can now _always_ just group by tags, and it'll just magically work.
    ///
    /// this approach also gives us the property that we have a deterministic subset of the tags
    /// (and of strictly decreasing cardinality!) tags downstream of unions. this may (?)
    /// improve cache locality, but could perhaps also allow further optimizations later (?).
    fn find_union_groupings(
        &self,
        paths: &[RawReplayPath],
        assigned_tags: &[Tag],
    ) -> HashMap<(NodeIndex, usize), Tag> {
        let union_suffixes = paths
            .iter()
            .enumerate()
            .flat_map(|(pi, path)| {
                let graph = &self.graph;
                path.segments().iter().enumerate().filter_map(
                    move |(at, &IndexRef { node, .. })| {
                        let n = &graph[node];
                        if n.is_union() && !n.is_shard_merger() {
                            let suffix = match path.segments().get((at + 1)..) {
                                Some(x) => x,
                                None => {
                                    // FIXME(eta): would like to return a proper internal!() here
                                    return None;
                                }
                            };
                            Some(((node, suffix), pi))
                        } else {
                            None
                        }
                    },
                )
            })
            .fold(BTreeMap::new(), |mut map, (key, pi)| {
                #[allow(clippy::unwrap_or_default)]
                map.entry(key).or_insert_with(Vec::new).push(pi);
                map
            });

        // map each suffix-sharing group of paths at each union to one tag at that union
        union_suffixes
            .into_iter()
            .flat_map(|((union, _suffix), paths)| {
                // at this union, all the given paths share a suffix
                // make all of the paths use a single identifier from that point on
                let tag_all_as = assigned_tags[paths[0]];
                paths.into_iter().map(move |pi| ((union, pi), tag_all_as))
            })
            .collect()
    }

    /// Find the ancestors of any joins for the given path. This is to ensure that all parents
    /// are `Ready` (and will have been sent an `IsReady` message) before we start a replay.
    ///
    /// We assume that since the node traversal is topologically sorted (see
    /// `Materializations::commit()`), any parent node would have been sent a `Ready` message.
    ///
    /// To do this, we look for all join nodes in the provided `path`, and walk the tree of
    /// the each parent. We then find all fully materialized nodes in all ancestors.
    fn find_additional_ancestors(
        &self,
        path: &RawReplayPath,
    ) -> HashSet<(DomainIndex, LocalNodeIndex)> {
        let mut additional_ancestors = HashSet::new();

        let mut seen = HashSet::new();
        for segment in path.segments() {
            let n = &self.graph[segment.node];
            if n.is_join().is_ok_and(|b| b) {
                // as the `path.segments()` iterator traverses downward through the graph,
                // we can skip ancestors of the current segment we've already looked at.
                let mut queue = n.ancestors().unwrap_or_default();
                queue.retain(|a| !seen.contains(a));

                while let Some(parent) = queue.pop() {
                    let node = &self.graph[parent];
                    if node.is_base() || node.requires_full_materialization() {
                        additional_ancestors.insert((node.domain(), node.local_addr()));
                    } else {
                        queue.extend(node.ancestors().unwrap_or_default());
                    }

                    seen.insert(segment.node);
                }
            }
        }

        additional_ancestors
    }

    /// Finds the appropriate replay paths for the given index, and inform all domains on those
    /// paths about them. It also notes if any data backfills will need to be run, which is
    /// eventually reported back by `finalize`.
    #[allow(clippy::cognitive_complexity, clippy::unreachable)]
    pub(super) fn add(&mut self, index_on: Index) -> Result<(), ReadySetError> {
        // if we are recovering, we must build the paths again. Otherwise
        // if we're full and we already have some paths added... (either this run, or from previous
        // runs)
        if !self.dmp.is_recovery() && !self.partial && (!self.paths.is_empty() || self.has_paths) {
            // ...don't add any more replay paths, because fully materialized nodes should not have
            // one replay path per index. that would cause us to replay several times, even though
            // one full replay should always be sufficient.  we do need to keep track of the fact
            // that there should be an index here though.
            self.indexes.entry(index_on).or_default();
            return Ok(());
        }

        let mut paths = self.paths(&index_on)?;
        // Discard paths for indices we already have.
        //
        // We do this both because we generally want to be as idempotent as possible, and (perhaps
        // more importantly) in case we get passed two subsequent indexes for generated columns that
        // happen to remap to the same set of columns upstream
        paths.retain(|p| {
            if p.has_extension() {
                p.target().index.iter().all(|idx| {
                    self.parent_indexes
                        .get(&p.target().node)
                        .is_none_or(|idxs| !idxs.contains(idx))
                })
            } else {
                p.target()
                    .index
                    .iter()
                    .all(|idx| !self.indexes.contains_key(idx))
            }
        });

        if paths.is_empty() {
            // If we aren't making any replay paths for this index, we *do* still need to make sure
            // the node actually has the index. This gets hit if the node has generated columns,
            // since in that case we make an index for the target of the downstream replay path, and
            // an index for the source of the upstream path. If the second one gets `add`ed first,
            // it won't create the index, since the actual target index of the replay is different
            // than the one that the downstream replay path wants to do a lookup into.
            self.indexes.entry(index_on).or_default();
            return Ok(());
        }

        invariant!(
            paths
                .iter()
                .skip(1)
                .all(|p| { p.last_segment().index == paths[0].last_segment().index }),
            "All paths should have the same index"
        );
        #[allow(clippy::unwrap_used)] // paths can't be empty
        let target_index = if let Some(idx) = paths.first().unwrap().target().index.clone() {
            // This might be different than `index_on` if this replay path is for a generated set of
            // columns
            idx
        } else {
            index_on.clone()
        };

        let assigned_tags: Vec<_> = paths
            .iter()
            .map(|path| self.m.tag_for_path(&index_on, path))
            .collect();
        // find all paths through each union with the same suffix
        let path_grouping = self.find_union_groupings(&paths, &assigned_tags);

        // inform domains about replay paths
        for (pi, path) in paths.into_iter().enumerate() {
            let tag = assigned_tags[pi];
            // TODO(eta): figure out a way to check partial replay path idempotency
            self.paths.insert(
                tag,
                (
                    index_on.clone(),
                    path.segments()
                        .iter()
                        .map(|&IndexRef { node, .. }| node)
                        .collect(),
                ),
            );

            if path.has_extension() {
                if let Some(index) = path.target().index.clone() {
                    self.parent_indexes
                        .entry(path.target().node)
                        .or_default()
                        .insert(index);
                }
                self.indexes.entry(index_on.clone()).or_default().push(tag);
            } else {
                self.indexes
                    .entry(target_index.clone())
                    .or_default()
                    .push(tag);
            }

            // what index are we using for partial materialization (if any)?
            let mut partial: Option<Index> = None;
            #[allow(clippy::unwrap_used)] // paths for partial indices must always be partial
            if self.partial {
                partial = Some(path.source().index.clone().unwrap());
            }

            // if this is a partial replay path, and the target node is sharded, then we need to
            // make sure that the last sharder on the path knows to only send the replay response
            // to the requesting shard, as opposed to all shards. in order to do that, that sharder
            // needs to know who it is!
            let mut partial_unicast_sharder = None;
            if partial.is_some() && !self.graph[path.target().node].sharded_by().is_none() {
                partial_unicast_sharder = path
                    .segments()
                    .iter()
                    .rev()
                    .map(|&IndexRef { node, .. }| node)
                    .find(|&ni| self.graph[ni].is_sharder());
            }

            // first, find out which domains we are crossing
            let mut segments: Vec<(
                DomainIndex,
                Vec<(NodeIndex, Option<Index>, /* is_target: */ bool)>,
            )> = Vec::new();
            let mut last_domain = None;
            for (i, IndexRef { node, index }) in
                path.segments_with_extension().iter().cloned().enumerate()
            {
                let domain = self.graph[node].domain();

                #[allow(clippy::unwrap_used)]
                if last_domain.is_none() || domain != last_domain.unwrap() {
                    segments.push((domain, Vec::new()));
                    last_domain = Some(domain);
                }

                invariant!(!segments.is_empty());

                #[allow(clippy::unwrap_used)] // checked by invariant!()
                segments.last_mut().unwrap().1.push((
                    node,
                    index,
                    /* is_target = */ i == path.target_index(),
                ));
            }

            invariant!(!segments.is_empty());

            debug!(%tag, "domain replay path is {:?}", segments);

            // tell all the domains about their segment of this replay path
            let mut pending = None;
            let mut seen = HashSet::new();
            for (i, &(domain, ref nodes)) in segments.iter().enumerate() {
                invariant!(!nodes.is_empty());
                // TODO:
                //  a domain may appear multiple times in this list if a path crosses into the same
                //  domain more than once. currently, that will cause a deadlock.
                if seen.contains(&domain) {
                    trace!(
                        "{}",
                        Graphviz {
                            graph: self.graph,
                            node_sizes: None,
                            materializations: self.m,
                            domain_nodes: None,
                            reachable_from: None,
                        }
                    );
                    internal!("detected A-B-A domain replay path");
                }
                seen.insert(domain);

                if i == 0 {
                    // check to see if the column index is generated; if so, inform the domain
                    #[allow(clippy::unwrap_used)] // checked by invariant!()
                    let first = nodes.first().unwrap();
                    if let Some(ref index) = first.1 {
                        if self.graph[first.0].is_internal() {
                            if let ColumnSource::GeneratedFromColumns(generated_from) =
                                self.graph[first.0].column_source(&index.columns)
                            {
                                debug!(
                                    domain = %domain.index(),
                                    ?tag,
                                    on_node = %first.0.index(),
                                    generated_columns = ?index.columns,
                                    ?generated_from,
                                    "telling domain about generated columns",
                                );

                                self.dmp.add_message(
                                    domain,
                                    DomainRequest::GeneratedColumns {
                                        node: self.graph[first.0].local_addr(),
                                        index: index.clone(),
                                        tag,
                                    },
                                )?;
                            }
                        }
                    }
                }

                // we're not replaying through the starter node
                let skip_first = usize::from(i == 0);

                // use the local index for each node
                let locals: Vec<_> = nodes
                    .iter()
                    .skip(skip_first)
                    .map(|&(ni, ref key, is_target)| ReplayPathSegment {
                        node: self.graph[ni].local_addr(),
                        partial_index: key.clone(),
                        force_tag_to: path_grouping.get(&(ni, pi)).copied(),
                        is_target,
                    })
                    .collect();

                // the first domain in the chain may *only* have the source node
                // in which case it doesn't need to know about the path
                let locals = if let Ok(locals) = Vec1::try_from(locals) {
                    locals
                } else {
                    invariant_eq!(i, 0);
                    continue;
                };

                #[allow(clippy::expect_used)]
                let our_replicas = self
                    .dmp
                    .num_replicas(domain)
                    .expect("Domain should exist at this point");
                let source_replicas = segments
                    .first()
                    .and_then(|(source_domain, _)| self.dmp.num_replicas(*source_domain).ok());
                let replica_fanout = match source_replicas {
                    Some(source_replicas) if source_replicas == our_replicas => {
                        // Same number of replicas, no fanount
                        false
                    }

                    Some(source_replicas) => {
                        invariant_eq!(
                            source_replicas,
                            1,
                            "Can't currently go from replicated n-ways to replicated m-ways"
                        );
                        // Replicating 1-way -> replicating n-ways
                        true
                    }
                    None => {
                        // Since we iterate in topological order, this shouldn't happen (we should
                        // have set the number of replicas for the domain by
                        // now)
                        internal!("Could not find replicas at source of replay path")
                    }
                };

                // build the message we send to this domain to tell it about this replay path.
                let mut setup = DomainRequest::SetupReplayPath {
                    tag,
                    source: None,
                    source_index: path.source().index.clone(),
                    path: locals,
                    notify_done: false,
                    partial_unicast_sharder,
                    trigger: TriggerEndpoint::None,
                    replica_fanout,
                };

                // the first domain also gets to know source node
                if i == 0 {
                    if let DomainRequest::SetupReplayPath { ref mut source, .. } = setup {
                        *source = Some(self.graph[nodes[0].0].local_addr());
                    }
                }

                if let Some(ref key) = partial {
                    // for partial materializations, nodes need to know how to trigger replays
                    if let DomainRequest::SetupReplayPath {
                        ref mut trigger, ..
                    } = setup
                    {
                        if segments.len() == 1 {
                            // replay is entirely contained within one domain
                            *trigger = TriggerEndpoint::Local(key.clone());
                        } else if i == 0 {
                            // first domain needs to be told about partial replay trigger
                            *trigger = TriggerEndpoint::Start(key.clone());
                        } else if i == segments.len() - 1 {
                            // if the source is sharded, we need to know whether we should ask all
                            // the shards, or just one. if the replay key is the same as the
                            // sharding key, we just ask one, and all is good. if the replay key
                            // and the sharding key differs, we generally have to query *all* the
                            // shards.
                            //
                            // there is, however, an exception to this: if we have two domains that
                            // have the same sharding, but a replay path between them on some other
                            // key than the sharding key, the right thing to do is to *only* query
                            // the same shard as ourselves. this is because any answers from other
                            // shards would necessarily just be with records that do not match our
                            // sharding key anyway, and that we should thus never see.

                            // Note : segments[0] looks something like this :
                            // ( DomainIndex(0),
                            //     [
                            //          (NodeIndex(1), Some([1])),
                            //          (NodeIndex(3), Some([1])),
                            //          (NodeIndex(4), Some([0])),
                            //          (NodeIndex(11), Some([0]))
                            //     ]
                            // )
                            //
                            // NOTE(eta): I have mixed feelings about how the writer of the above
                            //            note thought to be helpful and put the structure thing
                            //            there, but did not think to be helpful enough to refactor
                            //            it to use a more sane data structure...
                            //
                            let first_domain_segments = &segments[0].1;
                            invariant!(!first_domain_segments.is_empty());

                            let first_domain_node_key = &first_domain_segments[0];

                            let src_sharding = self.graph[first_domain_node_key.0].sharded_by();
                            let shards = src_sharding.shards().unwrap_or(1);
                            let lookup_key_index_to_shard = match src_sharding {
                                Sharding::Random(..) => None,
                                Sharding::ByColumn(c, _) => {
                                    // we want to check the source of the key column. If the source
                                    // node is sharded by that
                                    // column, we are able to ONLY look at a single
                                    // shard on the source. Otherwise, we need to check all of the
                                    // shards.
                                    let key_column_source = &first_domain_node_key.1;
                                    match key_column_source {
                                        Some(source_index) => {
                                            if source_index.len() == 1 {
                                                if source_index[0] == c {
                                                    // the source node is sharded by the key column.
                                                    Some(0)
                                                } else {
                                                    // the node is sharded by a different column
                                                    // than
                                                    // the key column, so we need to go ahead and
                                                    // query all
                                                    // shards. BUMMER.
                                                    None
                                                }
                                            } else {
                                                // we're using a compound key to look up into a node
                                                // that's
                                                // sharded by a single column. if the sharding key
                                                // is one
                                                // of the lookup keys, then we indeed only need to
                                                // look at
                                                // one shard, otherwise we need to ask all
                                                source_index
                                                    .columns
                                                    .iter()
                                                    .position(|source_column| source_column == &c)
                                            }
                                        }
                                        // This means the key column has no provenance in
                                        // the source. This could be because it comes from multiple
                                        // columns.
                                        // Or because the node is fully materialized so replays are
                                        // not necessary.
                                        None => None,
                                    }
                                }
                                s if s.is_none() => None,
                                s => internal!("unhandled new sharding pattern {:?}", s),
                            };

                            let selection = if let Some(i) = lookup_key_index_to_shard {
                                // if we are not sharded, all is okay.
                                //
                                // if we are sharded:
                                //
                                //  - if there is a shuffle above us, a shard merger + sharder above
                                //    us will ensure that we hear the replay response.
                                //
                                //  - if there is not, we are sharded by the same column as the
                                //    source. this also means that the replay key in the destination
                                //    is the sharding key of the destination. to see why, consider
                                //    the case where the destination is sharded by x. the source
                                //    must also be sharded by x for us to be in this case. we also
                                //    know that the replay lookup key on the source must be x since
                                //    lookup_on_shard_key == true. since no shuffle was introduced,
                                //    src.x must resolve to dst.x assuming x is not aliased in dst.
                                //    because of this, it should be the case that KeyShard ==
                                //    SameShard; if that were not the case, the value in dst.x
                                //    should never have reached dst in the first place.
                                SourceSelection::KeyShard {
                                    key_i_to_shard: i,
                                    nshards: shards,
                                }
                            } else {
                                // replay key != sharding key
                                // normally, we'd have to query all shards, but if we are sharded
                                // the same as the source (i.e., there are no shuffles between the
                                // source and us), then we should *only* query the same shard of
                                // the source (since it necessarily holds all records we could
                                // possibly see).
                                //
                                // note that the no-sharding case is the same as "ask all shards"
                                // except there is only one (shards == 1).
                                if src_sharding.is_none()
                                    || segments
                                        .iter()
                                        .flat_map(|s| s.1.iter())
                                        .any(|&(n, _, _)| self.graph[n].is_shard_merger())
                                {
                                    SourceSelection::AllShards(shards)
                                } else {
                                    SourceSelection::SameShard
                                }
                            };

                            debug!(policy = ?selection, %tag, "picked source selection policy");
                            {
                                *trigger = TriggerEndpoint::End(selection, segments[0].0);
                            }
                        }
                    }
                } else {
                    // for full materializations, we need to identifiy the parents that
                    // are also fully materialized, and make sure to wait for them to be `Ready`.
                    let additional_ancestors = self.find_additional_ancestors(&path);

                    // for full materializations, the last domain should report when it's done
                    if i == segments.len() - 1 {
                        if let DomainRequest::SetupReplayPath {
                            ref mut notify_done,
                            ..
                        } = setup
                        {
                            *notify_done = true;
                            invariant!(pending.is_none());

                            let first_domain_segments_data = &segments[0];
                            invariant!(!first_domain_segments_data.1.is_empty());

                            let first_domain_node_key = &first_domain_segments_data.1[0];

                            {
                                pending = Some(PendingReplay {
                                    tag,
                                    source: self.graph[first_domain_node_key.0].local_addr(),
                                    source_domain: first_domain_segments_data.0,
                                    target_domain: segments
                                        .last()
                                        .ok_or_else(|| internal_err!())?
                                        .0,
                                    additional_ancestors,
                                });
                            }
                        }
                    }
                }

                if i != segments.len() - 1 {
                    // since there is a later domain, the last node of any non-final domain
                    // must either be an egress or a Sharder. If it's an egress, we need
                    // to tell it about this replay path so that it knows
                    // what path to forward replay packets on.
                    #[allow(clippy::unwrap_used)] // nodes>0 checked by invariant
                    let n = &self.graph[nodes.last().unwrap().0];
                    if n.is_egress() {
                        let later_domain_segments = &segments[i + 1].1;
                        invariant!(!later_domain_segments.is_empty());
                        let (ingress_node, _, _) = later_domain_segments[0];
                        self.dmp.add_message(
                            domain,
                            DomainRequest::AddEgressTag {
                                egress_node: n.local_addr(),
                                tag,
                                ingress_node,
                            },
                        )?;
                    } else {
                        invariant!(n.is_sharder());
                    }
                }

                trace!(domain = %domain.index(), "telling domain about replay path");
                self.dmp.add_message(domain, setup)?;
            }

            if !self.partial && !self.graph[self.node].is_base() {
                // this path requires doing a replay and then waiting for the replay to finish
                if let Some(pending) = pending {
                    self.pending.push(pending);
                } else {
                    internal!(
                        "no replay planned for fully materialized non-base node {}!",
                        self.node.index()
                    );
                }
            }
        }

        Ok(())
    }

    /// Instructs the target node to set up appropriate state for any new indices that have been
    /// added. For new indices added to full materializations, this may take some time (a
    /// re-indexing has to happen), whereas for new indices to partial views it should be nearly
    /// instantaneous.
    ///
    /// Returns a list of backfill replays that need to happen before the migration is complete,
    /// and a set of replay paths for this node indexed by tag.
    pub(super) fn finalize(
        mut self,
    ) -> ReadySetResult<(Vec<PendingReplay>, HashMap<Tag, (Index, Vec<NodeIndex>)>)> {
        let our_node = &self.graph[self.node];
        let s = if let Some(r) = our_node.as_reader() {
            let index = r
                .index()
                .ok_or_else(|| internal_err!("Reader has no key"))?
                .clone();

            if self.partial {
                invariant!(r.is_materialized());

                // the node index we were created with is in graph...
                let last_domain = self.graph[self.node].domain();
                let num_shards = self.dmp.num_shards(last_domain)?;

                // since we're partially materializing a reader node,
                // we need to give it a way to trigger replays.
                PrepareStateKind::PartialReader {
                    node_index: self.node,
                    num_columns: self.graph[self.node].columns().len(),
                    index,
                    trigger_domain: last_domain,
                    num_shards,
                }
            } else {
                PrepareStateKind::FullReader {
                    num_columns: self.graph[self.node].columns().len(),
                    index,
                    node_index: self.node,
                }
            }
        } else {
            let weak_indices = self.m.added_weak.remove(&self.node).unwrap_or_default();

            if self.partial {
                let strict_indices = self.indexes.drain().collect();
                PrepareStateKind::Partial {
                    strict_indices,
                    weak_indices,
                }
            } else {
                let strict_indices = self.indexes.drain().map(|(k, _)| k).collect();
                PrepareStateKind::Full {
                    strict_indices,
                    weak_indices,
                }
            }
        };

        self.dmp.add_message(
            our_node.domain(),
            DomainRequest::PrepareState {
                node: our_node.local_addr(),
                state: s,
            },
        )?;

        if self.m.config.packet_filters_enabled {
            self.setup_packet_filter()?;
        }

        if !self.partial {
            // if we're constructing a new view, there is no reason to replay any given path more
            // than once. we do need to be careful here though: the fact that the source and
            // destination of a path are the same does *not* mean that the path is the same (b/c of
            // unions), and we do not want to eliminate different paths!
            let mut distinct_paths = HashSet::new();
            let paths = &self.paths;
            self.pending.retain(|p| {
                // keep if this path is different
                if let Some(path) = paths.get(&p.tag) {
                    distinct_paths.insert(path)
                } else {
                    // FIXME(eta): proper error handling here! (would be nice to have try_retain)
                    false
                }
            });
        } else {
            invariant!(self.pending.is_empty());
        }
        Ok((self.pending, self.paths))
    }

    fn setup_packet_filter(&mut self) -> ReadySetResult<()> {
        // If the node is partial and also a reader, then traverse the
        // graph upwards to notify the egress node that it should filter
        // any packet that was not requested.
        let our_node = &self.graph[self.node];
        if self.partial && our_node.is_reader() {
            // Since reader nodes belong to their own domains, their
            // domains should consist only of them + an ingress node.
            // It's fair to assume that the reader node has an ingress node as an ancestor.
            let ingress_opt = self
                .graph
                .neighbors_directed(self.node, petgraph::Incoming)
                .find(|&n| self.graph[n].is_ingress());
            let ingress = match ingress_opt {
                None => internal!("The current node is a reader, it MUST belong in its own domain, and therefore must be an ingress node ancestor."),
                Some(i) => i
            };
            // Now we look for the egress node, which should be an ancestor of the ingress node.
            let egress_opt = self
                .graph
                .neighbors_directed(ingress, petgraph::Incoming)
                .find(|&n| self.graph[n].is_egress());
            let egress = match egress_opt {
                // If an ingress node does not have an incoming egress node, that means this reader
                // domain is behind a shard merger.
                // We skip the packet filter setup for now.
                // TODO(fran): Implement packet filtering for shard mergers (https://readysettech.atlassian.net/browse/ENG-183).
                None => return Ok(()),
                Some(e) => e,
            };
            // Get the egress node's local address within that domain.
            let egress_local_addr = self.graph[egress].local_addr();
            // Communicate the egress node's domain that any packet sent
            // to the reader's domain ingress node should filter any
            // packets not previously requested.
            self.dmp.add_message(
                self.graph[egress].domain(),
                DomainRequest::AddEgressFilter {
                    egress_node: egress_local_addr,
                    target_node: ingress,
                },
            )?;
            Ok(())
        } else {
            Ok(())
        }
    }
}
