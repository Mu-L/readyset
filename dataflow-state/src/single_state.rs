use std::rc::Rc;

use common::{IndexType, SizeOf};
use itertools::Either;
use rand::distr::Uniform;
use readyset_client::internal::Index;
use readyset_client::KeyComparison;
use readyset_data::{Bound, DfValue, RangeBounds};
use vec1::Vec1;

use crate::keyed_state::KeyedState;
use crate::mk_key::MakeKey;
use crate::{LookupResult, PointKey, RangeKey, RangeLookupResult, RecordResult, Row, Rows};

/// A single index of a [`MemoryState`].
///
/// SingleState, which is a wrapper around [`KeyedState`] with extra information about keys and
/// partial, are associative maps from some subset of the columns in a row, to those rows
/// themselves. Internally, as specified by the [`Index`] passed at construction, KeyedState (and
/// hence SingleState) can be backed by either a [`BTreeMap`](std::collections::BTreeMap) or an
/// [`IndexMap`](indexmap::IndexMap) (which is similar to a [`HashMap`](std::collections::HashMap)).
///
/// Any operations on a SingleState that are unsupported by the index type, such as inserting or
/// looking up ranges in a [`HashMap`](readyset_client::IndexType::HashMap) index, will panic, as
/// mixing up index types is an unrecoverable violation of a broad system invariant.
pub(super) struct SingleState {
    /// The column indices and index type that this index is keyed on
    index: Index,

    /// The map containing the state itself.
    ///
    /// Invariant: The length of keys supported by `state` must be equal to `key.len()`
    state: KeyedState,

    /// Is this state partial?
    ///
    /// If this is `false`, lookups (via [`lookup`] or [`lookup_range`]) can never return misses
    partial: bool,

    /// Denormalized cache of the number of rows stored in this index
    row_count: usize,
}

impl SingleState {
    /// Construct a new, empty [`SingleState`] for the given `index`. If `partial`
    pub(super) fn new(index: Index, partial: bool) -> Self {
        let mut state = KeyedState::from(&index);
        if !partial && index.index_type == IndexType::BTreeMap {
            // For fully materialized indices, we never miss - so mark that the full range of keys
            // has been filled.
            state.insert_full_range();
        }
        Self {
            index,
            state,
            partial,
            row_count: 0,
        }
    }

    /// Inserts the given row, or returns false if a hole was encountered (and the record hence
    /// not inserted).
    pub(super) fn insert_row(&mut self, row: Row) -> bool {
        let added = self.state.insert(&self.index.columns, row, self.partial);
        if added {
            self.row_count += 1;
        }
        added
    }

    /// Attempt to remove row `r`.
    pub(super) fn remove_row(&mut self, r: &[DfValue], hit: &mut bool) -> Option<Row> {
        let row = self.state.remove(&self.index.columns, r, Some(hit));
        if row.is_some() {
            self.row_count = self.row_count.saturating_sub(1);
        }
        row
    }

    fn mark_point_filled(&mut self, key: Vec1<DfValue>) {
        let mut key = key.into_iter();
        let replaced = match self.state {
            KeyedState::AllRows(_) => {
                // No-op (can't be partial)
                return;
            }
            KeyedState::SingleBTree(ref mut map) => {
                assert_eq!(key.len(), 1);
                map.insert(key.next().unwrap(), Rows::default())
            }
            KeyedState::DoubleBTree(ref mut map) => {
                assert_eq!(key.len(), 2);
                map.insert((key.next().unwrap(), key.next().unwrap()), Rows::default())
            }
            KeyedState::TriBTree(ref mut map) => {
                assert_eq!(key.len(), 3);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
            KeyedState::QuadBTree(ref mut map) => {
                assert_eq!(key.len(), 4);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
            KeyedState::QuinBTree(ref mut map) => {
                assert_eq!(key.len(), 5);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
            KeyedState::SexBTree(ref mut map) => {
                assert_eq!(key.len(), 6);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
            KeyedState::MultiBTree(ref mut map, len) => {
                // I hope LLVM optimizes away the unnecessary into_iter() -> collect()
                assert_eq!(key.len(), len);
                map.insert(key.collect(), Rows::default())
            }
            KeyedState::MultiHash(ref mut map, len) => {
                assert_eq!(key.len(), len);
                map.insert(key.collect(), Rows::default())
            }
            KeyedState::SingleHash(ref mut map) => {
                assert_eq!(key.len(), 1);
                map.insert(key.next().unwrap(), Rows::default())
            }
            KeyedState::DoubleHash(ref mut map) => {
                assert_eq!(key.len(), 2);
                map.insert((key.next().unwrap(), key.next().unwrap()), Rows::default())
            }
            KeyedState::TriHash(ref mut map) => {
                assert_eq!(key.len(), 3);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
            KeyedState::QuadHash(ref mut map) => {
                assert_eq!(key.len(), 4);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
            KeyedState::QuinHash(ref mut map) => {
                assert_eq!(key.len(), 5);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
            KeyedState::SexHash(ref mut map) => {
                assert_eq!(key.len(), 6);
                map.insert(
                    (
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                        key.next().unwrap(),
                    ),
                    Rows::default(),
                )
            }
        };
        assert!(replaced.is_none());
    }

    fn mark_range_filled(&mut self, range: (Bound<Vec1<DfValue>>, Bound<Vec1<DfValue>>)) {
        self.state.insert_range(range);
    }

    /// Marks the given key `filled` and returns the amount of memory bytes used to store
    /// the state.
    pub(super) fn mark_filled(&mut self, key: KeyComparison) {
        match key {
            KeyComparison::Equal(k) => self.mark_point_filled(k),
            KeyComparison::Range(range) => self.mark_range_filled(range),
        }
    }

    /// Remove all rows for the given `key`, and return the amount of memory freed in bytes
    ///
    /// # Panics
    ///
    /// * Panics if the `key` is a range, but the underlying KeyedState is backed by a HashMap
    /// * Panics if the underlying index has no columns
    pub(super) fn mark_hole(&mut self, key: &KeyComparison) -> usize {
        let removed: Box<dyn Iterator<Item = (Row, usize)>> = match key {
            KeyComparison::Equal(key) => match self.state {
                KeyedState::AllRows(_) => panic!("Empty-column index cannot be partial"),
                KeyedState::SingleBTree(ref mut m) => {
                    Box::new(m.remove(&(key[0])).into_iter().flatten())
                }
                KeyedState::DoubleBTree(ref mut m) => {
                    Box::new(m.remove(&MakeKey::from_key(key)).into_iter().flatten())
                }
                KeyedState::TriBTree(ref mut m) => {
                    Box::new(m.remove(&MakeKey::from_key(key)).into_iter().flatten())
                }
                KeyedState::QuadBTree(ref mut m) => {
                    Box::new(m.remove(&MakeKey::from_key(key)).into_iter().flatten())
                }
                KeyedState::QuinBTree(ref mut m) => {
                    Box::new(m.remove(&MakeKey::from_key(key)).into_iter().flatten())
                }
                KeyedState::SexBTree(ref mut m) => {
                    Box::new(m.remove(&MakeKey::from_key(key)).into_iter().flatten())
                }
                KeyedState::MultiBTree(ref mut m, len) => {
                    debug_assert_eq!(key.len(), len);
                    Box::new(m.remove(key.as_vec()).into_iter().flatten())
                }
                KeyedState::MultiHash(ref mut m, len) => {
                    debug_assert_eq!(key.len(), len);
                    Box::new(m.swap_remove(key.as_vec()).into_iter().flatten())
                }
                KeyedState::SingleHash(ref mut m) => {
                    Box::new(m.swap_remove(&(key[0])).into_iter().flatten())
                }
                KeyedState::DoubleHash(ref mut m) => Box::new(
                    m.swap_remove::<(DfValue, _)>(&MakeKey::from_key(key))
                        .into_iter()
                        .flatten(),
                ),
                KeyedState::TriHash(ref mut m) => Box::new(
                    m.swap_remove::<(DfValue, _, _)>(&MakeKey::from_key(key))
                        .into_iter()
                        .flatten(),
                ),
                KeyedState::QuadHash(ref mut m) => Box::new(
                    m.swap_remove::<(DfValue, _, _, _)>(&MakeKey::from_key(key))
                        .into_iter()
                        .flatten(),
                ),
                KeyedState::QuinHash(ref mut m) => Box::new(
                    m.swap_remove::<(DfValue, _, _, _, _)>(&MakeKey::from_key(key))
                        .into_iter()
                        .flatten(),
                ),
                KeyedState::SexHash(ref mut m) => Box::new(
                    m.swap_remove::<(DfValue, _, _, _, _, _)>(&MakeKey::from_key(key))
                        .into_iter()
                        .flatten(),
                ),
            },
            KeyComparison::Range(range) => {
                macro_rules! remove_range {
                    ($m: expr, $range: expr, $hint: ty) => {
                        Box::new(
                            $m.remove_range(<$hint as MakeKey<DfValue>>::from_range(range))
                                .flat_map(|(_, rows)| rows),
                        )
                    };
                }

                match self.state {
                    KeyedState::SingleBTree(ref mut m) => remove_range!(m, range, DfValue),
                    KeyedState::DoubleBTree(ref mut m) => remove_range!(m, range, (DfValue, _)),
                    KeyedState::TriBTree(ref mut m) => remove_range!(m, range, (DfValue, _, _)),
                    KeyedState::QuadBTree(ref mut m) => {
                        remove_range!(m, range, (DfValue, _, _, _))
                    }
                    KeyedState::QuinBTree(ref mut m) => {
                        remove_range!(m, range, (DfValue, _, _, _, _))
                    }
                    KeyedState::SexBTree(ref mut m) => {
                        remove_range!(m, range, (DfValue, _, _, _, _, _))
                    }
                    KeyedState::MultiBTree(ref mut m, _) => Box::new(
                        m.remove_range::<[DfValue], _>((
                            range.start_bound().map(Vec1::as_slice),
                            range.end_bound().map(Vec1::as_slice),
                        ))
                        .flat_map(|(_, rows)| rows),
                    ),
                    _ => {
                        #[allow(clippy::panic)] // Documented invariant
                        {
                            panic!("mark_hole with a range key called on a HashMap SingleState")
                        }
                    }
                }
            }
        };

        removed
            .filter(|(r, _)| Rc::strong_count(&r.0) == 1)
            .map(|(r, count)| r.deep_size_of() * count)
            .sum()
    }

    pub(super) fn clear(&mut self) {
        self.row_count = 0;
        match self.state {
            KeyedState::AllRows(ref mut rows) => rows.clear(),
            KeyedState::SingleBTree(ref mut map) => map.clear(),
            KeyedState::DoubleBTree(ref mut map) => map.clear(),
            KeyedState::TriBTree(ref mut map) => map.clear(),
            KeyedState::QuadBTree(ref mut map) => map.clear(),
            KeyedState::QuinBTree(ref mut map) => map.clear(),
            KeyedState::SexBTree(ref mut map) => map.clear(),
            KeyedState::MultiBTree(ref mut map, _) => map.clear(),
            KeyedState::SingleHash(ref mut map) => map.clear(),
            KeyedState::DoubleHash(ref mut map) => map.clear(),
            KeyedState::TriHash(ref mut map) => map.clear(),
            KeyedState::QuadHash(ref mut map) => map.clear(),
            KeyedState::QuinHash(ref mut map) => map.clear(),
            KeyedState::SexHash(ref mut map) => map.clear(),
            KeyedState::MultiHash(ref mut map, _) => map.clear(),
        };
    }

    /// Select and evict a random key from `Self::state`. Return the key and evicted rows.
    pub(super) fn evict_random<R: rand::Rng>(
        &mut self,
        rng: &mut R,
    ) -> Option<(Vec<DfValue>, Rows)> {
        self.state
            .evict_with_seed(rng.sample(Uniform::new_inclusive(usize::MIN, usize::MAX).unwrap()))
            .map(|(rows, key)| {
                self.row_count = self.row_count.saturating_sub(rows.len());
                (key, rows)
            })
    }

    /// Evicts a specified key from this state, returning the removed rows
    pub(super) fn evict_keys(&mut self, keys: &[KeyComparison]) -> Rows {
        keys.iter()
            .flat_map(|k| match k {
                KeyComparison::Equal(equal) => Either::Left(
                    self.state
                        .evict(equal)
                        .into_iter()
                        .flat_map(|r| r.into_iter().map(|(r, _)| r)),
                ),
                KeyComparison::Range(range) => {
                    Either::Right(self.state.evict_range(range).into_iter().map(|(r, _)| r))
                }
            })
            .collect()
    }

    pub(super) fn values<'a>(&'a self) -> Box<dyn Iterator<Item = &'a Rows> + 'a> {
        self.state.values()
    }

    /// Return a reference to this state's Index, which contains the list of columns it's keyed on
    /// and the index type
    pub(super) fn index(&self) -> &Index {
        &self.index
    }

    /// Return this state's index type
    pub(super) fn index_type(&self) -> IndexType {
        self.index().index_type
    }

    /// Return a slice containing the indices of the columns that this index is keyed on
    pub(super) fn columns(&self) -> &[usize] {
        &self.index.columns
    }

    pub(super) fn partial(&self) -> bool {
        self.partial
    }

    pub(super) fn key_count(&self) -> usize {
        self.state.key_count()
    }

    pub(super) fn row_count(&self) -> usize {
        self.row_count
    }

    pub(super) fn is_empty(&self) -> bool {
        self.row_count == 0
    }

    pub(super) fn lookup<'a>(&'a self, key: &PointKey) -> LookupResult<'a> {
        if let Some(rs) = self.state.lookup(key) {
            LookupResult::Some(RecordResult::Borrowed(rs))
        } else if self.partial() {
            // partially materialized, so this is a hole (empty results would be vec![])
            LookupResult::Missing
        } else {
            LookupResult::Some(RecordResult::Owned(vec![]))
        }
    }

    pub(super) fn lookup_range<'a>(&'a self, key: &RangeKey) -> RangeLookupResult<'a> {
        match self.state.lookup_range(key) {
            Ok(rs) => RangeLookupResult::Some(RecordResult::References(rs.collect())),
            Err(misses) if self.partial() => RangeLookupResult::Missing(misses),
            _ => RangeLookupResult::Some(RecordResult::Owned(vec![])),
        }
    }
}

#[cfg(test)]
mod tests {
    use readyset_data::Bound;
    use vec1::vec1;

    use super::*;

    #[test]
    fn mark_filled_point() {
        let mut state = SingleState::new(Index::new(IndexType::BTreeMap, vec![0]), true);
        state.mark_filled(KeyComparison::Equal(vec1![0.into()]));
        assert!(state.lookup(&PointKey::from([0.into()])).is_some())
    }

    #[test]
    fn mark_filled_range() {
        let mut state = SingleState::new(Index::new(IndexType::BTreeMap, vec![0]), true);
        state.mark_filled(KeyComparison::Range((
            Bound::Included(vec1![0.into()]),
            Bound::Excluded(vec1![5.into()]),
        )));
        assert!(state.lookup(&PointKey::from([0.into()])).is_some());
        assert!(state
            .lookup_range(&RangeKey::from(&(vec1![0.into()]..vec1![5.into()])))
            .is_some());
    }

    mod evict_keys {
        use vec1::vec1;

        use super::*;

        #[test]
        fn equal() {
            let mut state = SingleState::new(Index::new(IndexType::BTreeMap, vec![0]), true);
            let key = KeyComparison::Equal(vec1![0.into()]);
            state.mark_filled(key.clone());
            state.insert_row(vec![0.into(), 1.into()].into());
            state.evict_keys(&[key]);
            assert!(state.lookup(&PointKey::from([0.into()])).is_missing())
        }

        #[test]
        fn range() {
            let mut state = SingleState::new(Index::new(IndexType::BTreeMap, vec![0]), true);
            let key =
                KeyComparison::from_range(&(vec1![DfValue::from(0)]..vec1![DfValue::from(10)]));
            state.mark_filled(key.clone());
            assert!(state
                .lookup_range(&RangeKey::from(
                    &(vec1![DfValue::from(0)]..vec1![DfValue::from(10)])
                ))
                .is_some());

            state.insert_row(vec![0.into(), 1.into()].into());
            state.evict_keys(&[key]);
            assert!(state.lookup(&PointKey::from([0.into()])).is_missing());
            assert!(state
                .lookup_range(&RangeKey::from(
                    &(vec1![DfValue::from(0)]..vec1![DfValue::from(10)])
                ))
                .is_missing())
        }

        #[test]
        fn row_count_after_eviction() {
            let mut state = SingleState::new(Index::new(IndexType::HashMap, vec![0]), true);
            state.mark_filled(KeyComparison::Equal(
                Vec1::try_from(vec![1.into()]).unwrap(),
            ));
            state.insert_row(Row::from(vec![1.into(), 2.into()]));
            state.insert_row(Row::from(vec![1.into(), 3.into()]));
            assert_eq!(state.row_count, 2);
            let mut rng = rand::rng();
            state.evict_random(&mut rng);
            assert!(state.is_empty());
        }
    }
}
