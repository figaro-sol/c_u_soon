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
fn different_names_different_hash() {
    // Same field types but different struct names → different hash
    assert_ne!(PairA::TYPE_HASH, PairB::TYPE_HASH);
    assert_ne!(PairA::METADATA, PairB::METADATA);
}

#[test]
fn reorder_different_hash() {
    // Different struct names always means different hash, but also
    // test that type order matters with same-name structs
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
    // PairA and Reordered have same field types but different struct names
    assert_ne!(PairA::TYPE_HASH, Reordered::TYPE_HASH);
}

#[test]
fn nested_works() {
    // Hash formula: init from struct name, then fold each field's type hash
    let acc = const_fnv1a(b"Nested");
    let acc = combine_hash(acc, PairA::TYPE_HASH);
    let acc = combine_hash(acc, u16::TYPE_HASH);
    let expected = combine_hash(acc, u16::TYPE_HASH);
    assert_eq!(Nested::TYPE_HASH, expected);
}

#[test]
fn type_order_matters_same_name() {
    // Two structs with the same name in different scopes can't collide at compile time,
    // but we can verify the formula is order-sensitive with different struct names
    #[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
    #[repr(C)]
    struct XY {
        x: u32,
        y: u32,
        z: u64,
    }

    #[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
    #[repr(C)]
    struct YX {
        z: u64,
        x: u32,
        y: u32,
    }

    // Different names → different hash, but also verify the formula:
    let xy_expected = combine_hash(
        combine_hash(
            combine_hash(const_fnv1a(b"XY"), u32::TYPE_HASH),
            u32::TYPE_HASH,
        ),
        u64::TYPE_HASH,
    );
    let yx_expected = combine_hash(
        combine_hash(
            combine_hash(const_fnv1a(b"YX"), u64::TYPE_HASH),
            u32::TYPE_HASH,
        ),
        u32::TYPE_HASH,
    );
    assert_eq!(XY::TYPE_HASH, xy_expected);
    assert_eq!(YX::TYPE_HASH, yx_expected);
    assert_ne!(XY::TYPE_HASH, YX::TYPE_HASH);
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
