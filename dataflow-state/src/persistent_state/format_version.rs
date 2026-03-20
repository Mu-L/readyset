//! On-disk format versioning for persistent state.
//!
//! RocksDB keys are produced by a multi-step pipeline, and a change to *any* step produces
//! different on-disk bytes, making existing data unreadable. The pipeline is:
//!
//! 1. **`PointKey::from()`** — calls [`DfValue::normalize()`] on each value (e.g. normalizes
//!    `Decimal` representations).
//! 2. **`PointKey::serialize()`** — calls [`DfValue::transform_for_serialized_key()`] on each
//!    value (e.g. widens `Float` to `f64`, produces collation sort keys for text, normalizes
//!    `TimestampTz` via `normalize_for_key()`), then wraps multi-element keys in tuples.
//! 3. **`serialize_key()`** — wraps the serialized `PointKey` bytes with a length prefix and
//!    optional extra data (epoch + sequence number for non-unique keys).
//!
//! [`PERSISTENT_STATE_VERSION`] is stored in [`super::PersistentMeta`] alongside each RocksDB
//! database and checked at startup. If the persisted version does not match, the database is
//! deleted and re-snapshotted from upstream.

use std::sync::Arc;

use bit_vec::BitVec;
use mysql_time::MySqlTime;
use readyset_data::{Array, Collation, DfValue, TinyText};
use readyset_decimal::Decimal;

use super::{serialize_key, PointKey};

/// Version number for the on-disk persistent state format.
///
/// Bump this version when making ANY change that affects the on-disk byte representation of
/// stored data, including:
///
/// - Changes to `DfValue`'s `Serialize` or `Deserialize` impls (covers both row data and key
///   contents — row data is bincode-serialized `Vec<DfValue>` directly, keys go through the
///   pipeline below)
/// - Changes to [`DfValue::transform_for_serialized_key()`] (key normalization before
///   serialization)
/// - Changes to [`DfValue::normalize()`] (called when constructing [`PointKey`]s)
/// - Changes to [`PointKey`]'s `Serialize` impl (tuple/seq wrapping)
/// - Changes to [`serialize_key()`](super::serialize_key) (length-prefix wrapping, extra data
///   encoding)
pub(super) const PERSISTENT_STATE_VERSION: u8 = 6;

/// Returns labeled single-element `DfValue`s exercising each normalization path in the key
/// serialization pipeline.
///
/// Each entry is `(human_label, value)`. The label is used in test failure messages to
/// identify which key diverged. Sentinel variants (`Default`, `Max`, `PassThrough`) are
/// excluded: although `Default` and `Max` have working unit-variant `Serialize` impls,
/// they are not user-data and never appear in persisted base-table rows or keys.
/// `Default` is replaced before reaching the storage layer; `Max` is a transient
/// upper-bound marker for range scans; `PassThrough` carries an opaque type byte stream
/// that's never persisted as a key.
fn example_single_values() -> Vec<(&'static str, DfValue)> {
    vec![
        ("None", DfValue::None),
        ("Int(0)", DfValue::Int(0)),
        ("Int(MAX)", DfValue::Int(i64::MAX)),
        ("Int(MIN)", DfValue::Int(i64::MIN)),
        ("UnsignedInt(0)", DfValue::UnsignedInt(0)),
        ("UnsignedInt(MAX)", DfValue::UnsignedInt(u64::MAX)),
        ("Float(MAX)", DfValue::Float(f32::MAX)),
        ("Float(0)", DfValue::Float(0.0)),
        ("Float(MIN)", DfValue::Float(f32::MIN)),
        ("Double(MAX)", DfValue::Double(f64::MAX)),
        ("Double(0)", DfValue::Double(0.0)),
        ("Double(MIN)", DfValue::Double(f64::MIN)),
        ("Text", DfValue::Text("aaaaaaaaaaaaaaaaaa".into())),
        (
            "TinyText",
            DfValue::TinyText(TinyText::from_slice(b"a", Collation::Utf8).expect("valid tinytext")),
        ),
        (
            "TimestampTz",
            DfValue::TimestampTz("2023-12-16 17:44:00".parse().expect("valid timestamp")),
        ),
        (
            "ByteArray",
            DfValue::ByteArray(Arc::new(b"aaaaaaaaaaaa".to_vec())),
        ),
        ("Numeric(MIN)", DfValue::Numeric(Arc::new(Decimal::MIN))),
        ("Numeric(MAX)", DfValue::Numeric(Arc::new(Decimal::MAX))),
        (
            "Numeric(42.42)",
            DfValue::Numeric(Arc::new(Decimal::try_from(42.42).expect("valid decimal"))),
        ),
        (
            "Time",
            DfValue::Time(MySqlTime::from_bytes(b"1112").expect("valid time")),
        ),
        (
            "BitVector",
            DfValue::BitVector(Arc::new(BitVec::from_bytes(b"aaaaaaaaa"))),
        ),
        (
            "Array",
            DfValue::Array(Arc::new(Array::from(vec![DfValue::from("aaaaaaaaa")]))),
        ),
    ]
}

/// Builds a labeled set of serialized RocksDB keys exercising every normalization path in
/// the key serialization pipeline described in the [module docs](self).
///
/// Each entry is `(human_label, key_bytes)`. The label appears only in test failure
/// messages — it is *not* persisted in the golden file. Co-locating label and bytes in a
/// single function eliminates the parallel-`Vec` synchronization hazard.
///
/// Used by the `key_serialization_backwards_compatibility` test and the
/// `make_serialized_keys` example to produce/verify a golden reference file.
///
/// Each `DfValue` is run through the full pipeline:
///
/// 1. `PointKey::from()` — calls `DfValue::normalize()` (e.g. `Decimal` normalization)
/// 2. `PointKey::serialize()` — calls `DfValue::transform_for_serialized_key()` (e.g. float
///    widening, collation sort keys, `TimestampTz::normalize_for_key()`)
/// 3. `serialize_key()` — length-prefixed bincode with optional extra data
///
/// A change to any of these steps will produce different bytes, causing the golden-file test to
/// fail.
pub fn example_serialized_keys() -> Vec<(&'static str, Vec<u8>)> {
    let single_values = example_single_values();

    let mut keys: Vec<(&'static str, Vec<u8>)> = Vec::new();

    // Empty key (exercises PointKey::Empty -> serialize_unit())
    keys.push(("Empty", serialize_key(&PointKey::Empty, ())));

    // Single-element keys exercising each normalization path:
    //   - Float: widened to f64 by transform_for_serialized_key
    //   - Text/TinyText: collation sort key by transform_for_serialized_key
    //   - TimestampTz: normalize_for_key by transform_for_serialized_key
    //   - Numeric: Decimal::normalize by PointKey::from -> DfValue::normalize
    for (label, v) in &single_values {
        let pk = PointKey::from(std::iter::once(v.clone()));
        keys.push((label, serialize_key(&pk, ())));
    }

    // Multi-element keys exercising each PointKey tuple variant.
    // Double (2 elements)
    let double = PointKey::from(vec![DfValue::from(42_i64), DfValue::from("hello")]);
    keys.push(("Double(2-element)", serialize_key(&double, ())));

    // Tri (3 elements)
    let triple = PointKey::from(vec![
        DfValue::Float(1.5),
        DfValue::TimestampTz("2024-01-01 00:00:00".parse().expect("valid timestamp")),
        DfValue::Numeric(Arc::new(Decimal::try_from(99.99).expect("valid decimal"))),
    ]);
    keys.push(("Tri(3-element)", serialize_key(&triple, ())));

    // Quad (4 elements)
    let quad = PointKey::from(vec![
        DfValue::from(1_i64),
        DfValue::from(2_i64),
        DfValue::from(3_i64),
        DfValue::from(4_i64),
    ]);
    keys.push(("Quad(4-element)", serialize_key(&quad, ())));

    // Quin (5 elements)
    let quin = PointKey::from(vec![
        DfValue::from(1_i64),
        DfValue::from(2_i64),
        DfValue::from(3_i64),
        DfValue::from(4_i64),
        DfValue::from(5_i64),
    ]);
    keys.push(("Quin(5-element)", serialize_key(&quin, ())));

    // Sex (6 elements — last tuple variant before Multi/SerializeSeq at 7)
    let sex = PointKey::from(vec![
        DfValue::from(1_i64),
        DfValue::from(2_i64),
        DfValue::from(3_i64),
        DfValue::from(4_i64),
        DfValue::from(5_i64),
        DfValue::from(6_i64),
    ]);
    keys.push(("Sex(6-element)", serialize_key(&sex, ())));

    // Multi (7+ elements, exercises SerializeSeq path in PointKey::serialize)
    let multi = PointKey::from(vec![
        DfValue::from(1_i64),
        DfValue::from(2_i64),
        DfValue::from(3_i64),
        DfValue::from(4_i64),
        DfValue::from(5_i64),
        DfValue::from(6_i64),
        DfValue::from(7_i64),
    ]);
    keys.push(("Multi(7-element)", serialize_key(&multi, ())));

    // Key with extra data (simulates non-unique primary key with epoch+seq)
    let pk_with_extra = PointKey::from(std::iter::once(DfValue::from(100_i64)));
    keys.push((
        "Single+extra(epoch+seq)",
        serialize_key(&pk_with_extra, (1u64, 2u64)),
    ));

    keys
}

/// Builds an example "row" of `DfValue`s exercising every serializable variant. Row data in
/// RocksDB is stored as `bincode`-serialized `Vec<DfValue>` directly — *not* through the
/// key pipeline — so this covers a different code path than [`example_serialized_keys`].
///
/// Reuses [`example_single_values`] so that adding a new `DfValue` variant covers both the
/// key path and the row path automatically.
///
/// Used by the `row_serialization_backwards_compatibility` test and the
/// `make_serialized_row` example to produce/verify the reference file.
pub fn example_serialized_row() -> Vec<DfValue> {
    example_single_values()
        .into_iter()
        .map(|(_, v)| v)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use bincode::Options;
    use pretty_assertions::assert_eq;
    use readyset_data::DfValueKind;

    use super::*;

    /// Returns one canonical DfValue per serializable variant, alongside an exhaustive
    /// match that forces a compiler error when DfValue gains a variant.
    ///
    /// When a new variant is added: classify it in the match as `true` (serializable,
    /// stored as RocksDB keys) or `false` (sentinel). If `true`, add a representative
    /// to the list AND add entries to [`example_single_values()`].
    fn serializable_representatives() -> Vec<DfValue> {
        // Intentionally NOT using matches!() — the exhaustive match forces a compiler
        // error when DfValue gains a variant, ensuring this function stays current.
        #[allow(clippy::match_like_matches_macro)]
        fn is_serializable(v: &DfValue) -> bool {
            match v {
                DfValue::None
                | DfValue::Int(_)
                | DfValue::UnsignedInt(_)
                | DfValue::Float(_)
                | DfValue::Double(_)
                | DfValue::Text(_)
                | DfValue::TinyText(_)
                | DfValue::TimestampTz(_)
                | DfValue::Time(_)
                | DfValue::ByteArray(_)
                | DfValue::Numeric(_)
                | DfValue::BitVector(_)
                | DfValue::Array(_) => true,
                // Sentinels: never stored as RocksDB keys
                DfValue::PassThrough(_) | DfValue::Default | DfValue::Max => false,
            }
        }

        let reps = vec![
            DfValue::None,
            DfValue::Int(0),
            DfValue::UnsignedInt(0),
            DfValue::Float(0.0),
            DfValue::Double(0.0),
            DfValue::Text("".into()),
            DfValue::TinyText(TinyText::from_slice(b"", Collation::Utf8).expect("valid tinytext")),
            DfValue::TimestampTz("2023-01-01 00:00:00".parse().expect("valid timestamp")),
            DfValue::Time(MySqlTime::from_bytes(b"0000").expect("valid time")),
            DfValue::ByteArray(Arc::new(vec![])),
            DfValue::Numeric(Arc::new(Decimal::from(0))),
            DfValue::BitVector(Arc::new(BitVec::new())),
            DfValue::Array(Arc::new(Array::from(vec![]))),
        ];

        for v in &reps {
            assert!(is_serializable(v), "{v:?} classified as sentinel");
        }

        reps
    }

    /// Checks that [`example_single_values()`] covers every serializable DfValue variant.
    /// If this fails, you added a new DfValue variant without adding it to the golden-file
    /// inputs.
    #[test]
    fn example_keys_cover_all_serializable_variants() {
        let required: HashSet<DfValueKind> = serializable_representatives()
            .iter()
            .map(DfValueKind::from)
            .collect();

        let covered: HashSet<DfValueKind> = example_single_values()
            .iter()
            .map(|(_, v)| DfValueKind::from(v))
            .collect();

        let missing: Vec<_> = required.difference(&covered).collect();
        assert!(
            missing.is_empty(),
            "example_serialized_keys() is missing variants: {missing:?}"
        );
    }

    /// Checks that the full key serialization pipeline produces the same bytes as the reference
    /// file. If this test fails, you have made a backwards-incompatible change to the on-disk
    /// key format. In that case:
    ///
    /// 1. Bump [`PERSISTENT_STATE_VERSION`]
    /// 2. Run `cargo run -p dataflow-state --example make_serialized_keys`
    ///    to regenerate the reference file
    #[test]
    fn key_serialization_backwards_compatibility() {
        let current = example_serialized_keys();
        let reference: Vec<Vec<u8>> = bincode::options()
            .deserialize(include_bytes!("../../tests/serialized-keys.bincode"))
            .expect("failed to deserialize reference keys");
        assert_eq!(
            reference.len(),
            current.len(),
            "number of example keys changed (expected {}, got {}); regenerate the reference file",
            reference.len(),
            current.len(),
        );
        for (i, ((label, cur), refr)) in current.iter().zip(reference.iter()).enumerate() {
            assert_eq!(refr, cur, "key {i} ({label}) differs from reference");
        }
    }

    /// Checks that the bincode-serialized golden row deserializes back to the same
    /// `Vec<DfValue>` produced by [`example_serialized_row`]. Row data in RocksDB is stored
    /// as bincode `Vec<DfValue>` directly (not through the key pipeline), so this catches
    /// `DfValue::Deserialize` regressions that the key-format test would miss. If this test
    /// fails, you have made a backwards-incompatible change to `DfValue` deserialization. In
    /// that case:
    ///
    /// 1. Bump [`PERSISTENT_STATE_VERSION`]
    /// 2. Run `cargo run -p dataflow-state --example make_serialized_row`
    ///    to regenerate the reference file
    #[test]
    fn row_serialization_backwards_compatibility() {
        let current = example_serialized_row();
        let reference: Vec<DfValue> = bincode::options()
            .deserialize(include_bytes!("../../tests/serialized-row.bincode"))
            .expect("failed to deserialize reference row");
        assert_eq!(
            reference.len(),
            current.len(),
            "number of example values changed (expected {}, got {}); regenerate the reference file",
            reference.len(),
            current.len(),
        );
        for (i, ((label, expected), got)) in example_single_values()
            .iter()
            .zip(reference.iter())
            .enumerate()
        {
            assert_eq!(expected, got, "row[{i}] ({label}) deserialized differently");
        }
    }
}
