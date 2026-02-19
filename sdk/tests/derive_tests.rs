#![cfg(feature = "derive")]

use bytemuck::{Pod, Zeroable};
use c_u_soon::{combine_hash, const_fnv1a, StructMetadata, TypeHash};

#[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
#[repr(C)]
struct PairA {
    x: u32,
    y: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
#[repr(C)]
struct PairB {
    x: u32,
    y: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
#[repr(C)]
struct Reordered {
    y: u32,
    x: u32,
}

#[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
#[repr(C)]
struct Nested {
    inner: PairA,
    z: u16,
    w: u16,
}

#[test]
fn same_fields_same_hash() {
    // Same field names + types in same order → same hash
    assert_eq!(PairA::TYPE_HASH, PairB::TYPE_HASH);
    assert_eq!(PairA::METADATA, PairB::METADATA);
}

#[test]
fn reorder_different_hash() {
    // Field names are included in hash, so swapping field order changes the hash
    // even with same types
    #[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
    #[repr(C)]
    struct AB {
        a: u8,
        _pad_a: u8,
        b: u16,
    }

    #[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
    #[repr(C)]
    struct BA {
        b: u16,
        a: u8,
        _pad_a: u8,
    }

    assert_ne!(AB::TYPE_HASH, BA::TYPE_HASH);
}

#[test]
fn same_types_different_names_different_hash() {
    // PairA has fields (x: u32, y: u32), Reordered has (y: u32, x: u32)
    // Same types but field name order differs → different hash
    assert_ne!(PairA::TYPE_HASH, Reordered::TYPE_HASH);
}

#[test]
fn nested_works() {
    // Hash formula: for each field, combine_hash(combine_hash(acc, fnv1a(name)), type_hash)
    let acc = const_fnv1a(b"__struct_init__");
    let acc = combine_hash(combine_hash(acc, const_fnv1a(b"inner")), PairA::TYPE_HASH);
    let acc = combine_hash(combine_hash(acc, const_fnv1a(b"z")), u16::TYPE_HASH);
    let expected = combine_hash(combine_hash(acc, const_fnv1a(b"w")), u16::TYPE_HASH);
    assert_eq!(Nested::TYPE_HASH, expected);
}

#[test]
fn metadata_size_matches_sizeof() {
    assert_eq!(
        PairA::METADATA.type_size() as usize,
        core::mem::size_of::<PairA>()
    );
    assert_eq!(
        Nested::METADATA.type_size() as usize,
        core::mem::size_of::<Nested>()
    );
}

#[test]
fn struct_metadata_of_helper() {
    assert_eq!(StructMetadata::of::<PairA>(), PairA::METADATA);
}
