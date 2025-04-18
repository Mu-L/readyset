use readyset_client::KeyComparison;
use serde::{Deserialize, Serialize};
use vec_map::VecMap;

use crate::payload::packets::ReplayPiece;
use crate::payload::{self, Eviction, ReplayPieceContext, SenderReplication};
use crate::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct SharderTx {
    node: LocalNodeIndex,
    domain_index: DomainIndex,
    shard: usize,
    replication: SenderReplication,
}

impl SharderTx {
    fn send(
        &self,
        m: Packet,
        from_replica: usize,
        output: &mut dyn Executor,
    ) -> ReadySetResult<()> {
        match self.replication {
            SenderReplication::Same => output.send(
                ReplicaAddress {
                    domain_index: self.domain_index,
                    shard: self.shard,
                    replica: from_replica,
                },
                m,
            ),
            SenderReplication::Fanout { num_replicas } => {
                match m.replay_piece_context() {
                    Some(ReplayPieceContext::Partial {
                        requesting_replica, ..
                    }) => {
                        // If the message is a piece of a replay that was requested by a
                        // particular replica, only replay to that
                        // replica
                        invariant!(
                            *requesting_replica < num_replicas,
                            "Replica index for replay piece context out-of-bounds"
                        );
                        output.send(
                            ReplicaAddress {
                                domain_index: self.domain_index,
                                shard: self.shard,
                                replica: from_replica,
                            },
                            m,
                        );
                    }
                    Some(ReplayPieceContext::Full {
                        replicas: Some(replicas),
                        ..
                    }) => {
                        // Otherwise if the message is a piece of a full replay that was
                        // intended for only a particular set of replicas, only replay to those
                        // replicas
                        invariant!(
                            replicas.iter().all(|r| *r < num_replicas),
                            "Replica index(es) for full replay piece context out-of-bounds"
                        );
                        for replica in replicas {
                            output.send(
                                ReplicaAddress {
                                    domain_index: self.domain_index,
                                    shard: self.shard,
                                    replica: *replica,
                                },
                                m.clone(),
                            )
                        }
                    }
                    _ => {
                        // Otherwise, replay to all replicas
                        for replica in 0..num_replicas {
                            output.send(
                                ReplicaAddress {
                                    domain_index: self.domain_index,
                                    shard: self.shard,
                                    replica,
                                },
                                m.clone(),
                            )
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Sharder {
    txs: VecMap<SharderTx>,
    #[serde(skip)]
    sharded: VecMap<Packet>,
    shard_by: usize,
}

impl Clone for Sharder {
    fn clone(&self) -> Self {
        debug_assert!(self.txs.is_empty());

        Sharder {
            txs: Default::default(),
            sharded: Default::default(),
            shard_by: self.shard_by,
        }
    }
}

impl Sharder {
    pub fn new(by: usize) -> Self {
        Self {
            txs: Default::default(),
            shard_by: by,
            sharded: VecMap::default(),
        }
    }

    #[must_use]
    pub fn take(&mut self) -> Self {
        let txs = std::mem::take(&mut self.txs);
        Self {
            txs,
            sharded: VecMap::default(),
            shard_by: self.shard_by,
        }
    }

    pub fn add_sharded_child(
        &mut self,
        dst_domain: DomainIndex,
        dst_node: LocalNodeIndex,
        num_shards: usize,
        replication: SenderReplication,
    ) {
        debug_assert_eq!(self.txs.len(), 0);
        // TODO: add support for "shared" sharder?
        self.txs.extend((0..num_shards).map(|shard| {
            (
                shard,
                SharderTx {
                    node: dst_node,
                    domain_index: dst_domain,
                    shard,
                    replication,
                },
            )
        }))
    }

    pub fn sharded_by(&self) -> usize {
        self.shard_by
    }

    #[inline]
    fn to_shard(&self, r: &Record) -> usize {
        self.shard(&r[self.shard_by])
    }

    #[inline]
    fn shard(&self, dt: &DfValue) -> usize {
        crate::shard_by(dt, self.txs.len())
    }

    pub fn process(
        &mut self,
        m: &mut Option<Packet>,
        index: LocalNodeIndex,
        is_sharded: bool,
        is_last_sharder_for_tag: Option<bool>,
        replica: usize,
        output: &mut dyn Executor,
    ) -> ReadySetResult<()> {
        // we need to shard the records inside `m` by their key,
        let mut m = m.take().unwrap();
        for record in m.take_data() {
            let shard = self.to_shard(&record);
            let p = self.sharded.entry(shard).or_insert_with(|| m.clone());
            p.data_mut().push(record);
        }

        enum Destination {
            All,
            One(usize),
            Any,
        }

        let mut dest = Destination::Any;
        if let Packet::ReplayPiece(ReplayPiece {
            context: payload::ReplayPieceContext::Full { last: true, .. },
            ..
        }) = m
        {
            // this is the last replay piece for a full replay
            // we need to make sure it gets to every shard so they know to ready the node
            dest = Destination::All;
        } else if let Packet::ReplayPiece(ReplayPiece {
            context:
                payload::ReplayPieceContext::Partial {
                    requesting_shard, ..
                },
            ..
        }) = m
        {
            if let Some(true) = is_last_sharder_for_tag {
                // we are the last sharder and the replay target is sharded
                // so we need to make sure only that shard gets the replay response,
                // since the others aren't expecting it.
                dest = Destination::One(requesting_shard);
            } else {
                // either, we are not the last sharder on the replay path
                // or, the ultimate target of the replay is not sharded.
                // in either case, we need to forward to all shards, since there will
                // be a shard merger below us that expects a message from all shards.
                dest = Destination::All;
            }
        } else {
            invariant!(is_last_sharder_for_tag.is_none());
        }

        match dest {
            Destination::All => {
                // ensure that every shard gets a packet
                // note that m has no data, so m.clone() has no data
                for shard in 0..self.txs.len() {
                    self.sharded.entry(shard).or_insert_with(|| m.clone());
                }
            }
            Destination::One(shard) => {
                // ensure that the target shard gets a packet
                self.sharded.entry(shard).or_insert_with(|| m.clone());
                // and that no-one else does
                self.sharded.retain(|k, _| k == shard);
            }
            Destination::Any => {}
        }

        if is_sharded {
            // FIXME: we don't know how many shards in the destination domain our sibling Sharders
            // sent to, so we don't know what to put here. we *could* put self.txs.len() and send
            // empty messages to all other shards, which is probably pretty sensible, but that only
            // solves half the problem. the destination shard domains will then receive *multiple*
            // replay pieces for each incoming replay piece, and needs to combine them somehow.
            // it's unclear how we do that.
            unsupported!("we don't know how to shard a shard");
        }

        for tx in self.txs.values() {
            if let Some(mut m) = self.sharded.remove(tx.shard) {
                m.link_mut().src = index;
                m.link_mut().dst = tx.node;
                tx.send(m, replica, output)?;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_eviction(
        &mut self,
        key_columns: &[usize],
        tag: Tag,
        keys: &[KeyComparison],
        src: LocalNodeIndex,
        is_sharded: bool,
        replica: usize,
        output: &mut dyn Executor,
    ) -> ReadySetResult<()> {
        invariant!(!is_sharded);

        if key_columns.len() == 1 && key_columns[0] == self.shard_by {
            // Send only to the shards that must evict something.
            for key in keys {
                for shard in key.shard_keys(self.txs.len()) {
                    let dst = self.txs[shard].node;
                    let p = self.sharded.entry(shard).or_insert_with(|| {
                        Packet::Evict(Evict {
                            req: Eviction::Keys {
                                link: Link { src, dst },
                                keys: Vec::new(),
                                tag,
                            },
                            done: None,
                            barrier: 0,
                            credits: 0,
                        })
                    });
                    match *p {
                        Packet::Evict(Evict {
                            req: Eviction::Keys { ref mut keys, .. },
                            done: None,
                            barrier: 0,
                            credits: 0,
                        }) => keys.push(key.clone()),
                        _ => {
                            // TODO: Scoped for a future refactor:
                            // https://readysettech.atlassian.net/browse/ENG-455
                            unreachable!("received a non EvictKey packed in process_eviction")
                        }
                    }
                }
            }

            for (shard, tx) in self.txs.iter() {
                if let Some(shard) = self.sharded.remove(shard) {
                    tx.send(shard, replica, output)?;
                }
            }
        } else {
            invariant_eq!(!key_columns.len(), 0);
            invariant!(!key_columns.contains(&self.shard_by));

            // send to all shards
            for tx in self.txs.values() {
                tx.send(
                    Packet::Evict(Evict {
                        req: Eviction::Keys {
                            link: Link { src, dst: tx.node },
                            keys: keys.to_vec(),
                            tag,
                        },
                        done: None,
                        barrier: 0,
                        credits: 0,
                    }),
                    replica,
                    output,
                )?;
            }
        }

        Ok(())
    }
}
