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
fn same_layout_same_hash() {
    assert_eq!(PairA::TYPE_HASH, PairB::TYPE_HASH);
    assert_eq!(PairA::METADATA, PairB::METADATA);
}

#[test]
fn reorder_different_hash() {
    // PairA is (u32, u32) - same types in same order, but Reordered
    // has field names swapped. Since TypeHash hashes field *types* not names,
    // two structs with identical field types in identical order have the same hash.
    // Reordered has (u32, u32) in the same order, so same hash.
    // To test reorder sensitivity, use different types:
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
fn nested_works() {
    let expected = combine_hash(
        combine_hash(
            combine_hash(const_fnv1a(b"__struct_init__"), PairA::TYPE_HASH),
            u16::TYPE_HASH,
        ),
        u16::TYPE_HASH,
    );
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
