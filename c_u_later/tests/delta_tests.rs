use bytemuck::{Pod, Zeroable};
use c_u_later::CuLater;
use c_u_soon::TypeHash;

// --- Test structs ---

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct Simple {
    readonly: u32,
    #[program]
    #[authority]
    both: u16,
    #[program]
    program_only: u8,
    #[authority]
    authority_only: u8,
}

// Simple layout (8 bytes):
//   readonly:       offset 0, size 4
//   both:           offset 4, size 2
//   program_only:   offset 6, size 1
//   authority_only: offset 7, size 1
//
// SimpleProgramDelta: both (idx=0), program_only (idx=1)
// SimpleAuthorityDelta: both (idx=0), authority_only (idx=1)

// --- Basic tests ---

#[test]
fn new_delta_is_empty() {
    let d = SimpleProgramDelta::new();
    assert!(d.is_empty());
    assert!(d.to_write_specs().is_empty());
}

#[test]
fn set_one_field() {
    let mut d = SimpleProgramDelta::new();
    d.set_both(0x1234);
    assert!(!d.is_empty());

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].offset, 4); // offset of `both`
    assert_eq!(specs[0].data, &0x1234u16.to_le_bytes());
}

#[test]
fn set_multiple_fields() {
    let mut d = SimpleProgramDelta::new();
    d.set_both(0xABCD);
    d.set_program_only(0x42);

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 2);
    // Spec 0: both at offset 4
    assert_eq!(specs[0].offset, 4);
    assert_eq!(specs[0].data, &0xABCDu16.to_le_bytes());
    // Spec 1: program_only at offset 6
    assert_eq!(specs[1].offset, 6);
    assert_eq!(specs[1].data, &[0x42]);
}

#[test]
fn set_all_writable_fields() {
    let mut d = SimpleProgramDelta::new();
    d.set_both(1);
    d.set_program_only(2);
    assert_eq!(d.to_write_specs().len(), 2);

    let mut d = SimpleAuthorityDelta::new();
    d.set_both(3);
    d.set_authority_only(4);
    assert_eq!(d.to_write_specs().len(), 2);
}

#[test]
fn set_same_field_twice_last_value_wins() {
    let mut d = SimpleProgramDelta::new();
    d.set_both(0x1111);
    d.set_both(0x2222);

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].offset, 4);
    assert_eq!(specs[0].data, &0x2222u16.to_le_bytes());
}

// --- Wire format tests ---

#[test]
fn write_specs_byte_exact_match() {
    let mut d = SimpleAuthorityDelta::new();
    d.set_both(0x0102);
    d.set_authority_only(0xFF);

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].offset, 4); // offset of `both`
    assert_eq!(specs[0].data, &[0x02, 0x01]); // 0x0102 LE
    assert_eq!(specs[1].offset, 7); // offset of `authority_only`
    assert_eq!(specs[1].data, &[0xFF]);
}

// --- Builder chaining ---

#[test]
fn builder_chaining() {
    let mut d = SimpleProgramDelta::new();
    d.set_both(10).set_program_only(20);
    assert_eq!(d.to_write_specs().len(), 2);
}

// --- Role isolation ---

#[test]
fn program_delta_has_program_fields_only() {
    let mut d = SimpleProgramDelta::new();
    d.set_both(1);
    d.set_program_only(2);
    assert_eq!(d.to_write_specs().len(), 2);
}

#[test]
fn authority_delta_has_authority_fields_only() {
    let mut d = SimpleAuthorityDelta::new();
    d.set_both(1);
    d.set_authority_only(2);
    assert_eq!(d.to_write_specs().len(), 2);
}

#[test]
fn shared_field_in_both_deltas() {
    let mut pd = SimpleProgramDelta::new();
    pd.set_both(42);
    let specs_p = pd.to_write_specs();

    let mut ad = SimpleAuthorityDelta::new();
    ad.set_both(42);
    let specs_a = ad.to_write_specs();

    // Both should produce identical specs (same offset, same data)
    assert_eq!(specs_p.len(), specs_a.len());
    assert_eq!(specs_p[0].offset, specs_a[0].offset);
    assert_eq!(specs_p[0].data, specs_a[0].data);
}

// --- Nested CuLater types ---

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct Inner {
    #[program]
    prog_field: u16,
    #[authority]
    auth_field: u16,
}

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct Outer {
    header: u32,
    #[program]
    inner_prog: Inner,
    #[authority]
    inner_auth: Inner,
    #[program]
    #[authority]
    inner_both: Inner,
}

// Outer layout (16 bytes):
//   header:     offset 0,  size 4
//   inner_prog: offset 4,  size 4
//   inner_auth: offset 8,  size 4
//   inner_both: offset 12, size 4

#[test]
fn nested_cu_later_set_whole_value() {
    let mut d = OuterProgramDelta::new();
    d.set_inner_prog(Inner {
        prog_field: 0x1234,
        auth_field: 0x5678,
    });

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].offset, 4); // offset of inner_prog
    assert_eq!(specs[0].data.len(), 4); // size of Inner
                                        // Inner is repr(C): prog_field then auth_field, both u16 LE
    assert_eq!(&specs[0].data[..2], &0x1234u16.to_le_bytes());
    assert_eq!(&specs[0].data[2..], &0x5678u16.to_le_bytes());
}

#[test]
fn nested_set_multiple() {
    let mut d = OuterProgramDelta::new();
    d.set_inner_prog(Inner {
        prog_field: 1,
        auth_field: 2,
    });
    d.set_inner_both(Inner {
        prog_field: 3,
        auth_field: 4,
    });

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].offset, 4); // inner_prog
    assert_eq!(specs[0].data.len(), 4);
    assert_eq!(specs[1].offset, 12); // inner_both
    assert_eq!(specs[1].data.len(), 4);
}

#[test]
fn nested_authority_delta() {
    let mut d = OuterAuthorityDelta::new();
    d.set_inner_auth(Inner {
        prog_field: 10,
        auth_field: 20,
    });

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].offset, 8); // offset of inner_auth
    assert_eq!(specs[0].data.len(), 4); // size of Inner
}

// --- Single writable field struct ---

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct SingleField {
    header: u32,
    #[program]
    value: u32,
}

#[test]
fn single_writable_field() {
    let mut d = SingleFieldProgramDelta::new();
    assert!(d.is_empty());

    d.set_value(0xDEADBEEF);
    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].offset, 4);
    assert_eq!(specs[0].data, &0xDEADBEEFu32.to_le_bytes());
}

// --- All fields writable ---

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct AllWritable {
    #[program]
    a: u32,
    #[program]
    b: u16,
    #[program]
    c: u8,
    #[program]
    d: u8,
}

#[test]
fn all_fields_writable() {
    let mut d = AllWritableProgramDelta::new();
    d.set_a(1).set_b(2).set_c(3).set_d(4);

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 4);
    // a: offset 0, size 4
    assert_eq!(specs[0].offset, 0);
    assert_eq!(specs[0].data, &1u32.to_le_bytes());
    // b: offset 4, size 2
    assert_eq!(specs[1].offset, 4);
    assert_eq!(specs[1].data, &2u16.to_le_bytes());
    // c: offset 6, size 1
    assert_eq!(specs[2].offset, 6);
    assert_eq!(specs[2].data, &[3u8]);
    // d: offset 7, size 1
    assert_eq!(specs[3].offset, 7);
    assert_eq!(specs[3].data, &[4u8]);
}

// --- No writable fields for a role ---

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct ProgramOnly {
    #[program]
    value: u32,
}

#[test]
fn empty_delta_for_role_without_fields() {
    let d = ProgramOnlyAuthorityDelta::new();
    assert!(d.is_empty());
    assert!(d.to_write_specs().is_empty());
}

// --- Padding fields excluded ---

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct WithPadding {
    #[program]
    value: u8,
    #[program]
    _pad: [u8; 3],
    #[program]
    big: u32,
}

#[test]
fn padding_fields_excluded_from_delta() {
    // _pad starts with '_' so should NOT appear in delta
    // Only value and big should have setters
    let mut d = WithPaddingProgramDelta::new();
    d.set_value(0xFF);
    d.set_big(0x12345678);

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 2);
    // value at offset 0, size 1
    assert_eq!(specs[0].offset, 0);
    assert_eq!(specs[0].data, &[0xFF]);
    // big at offset 4, size 4
    assert_eq!(specs[1].offset, 4);
    assert_eq!(specs[1].data, &0x12345678u32.to_le_bytes());
}

// --- Struct with u64 fields (larger offsets) ---

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater, Debug, PartialEq)]
#[repr(C)]
struct WideStruct {
    header: u64,
    #[program]
    counter: u64,
    #[program]
    timestamp: u64,
    footer: u64,
}

#[test]
fn larger_offsets_and_sizes() {
    // counter at offset 8, timestamp at offset 16
    let mut d = WideStructProgramDelta::new();
    d.set_counter(999);
    d.set_timestamp(123456789);

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 2);
    // counter: offset 8, size 8
    assert_eq!(specs[0].offset, 8);
    assert_eq!(specs[0].data, &999u64.to_le_bytes());
    // timestamp: offset 16, size 8
    assert_eq!(specs[1].offset, 16);
    assert_eq!(specs[1].data, &123456789u64.to_le_bytes());
}

// --- Subset of fields set ---

#[test]
fn only_second_field_set() {
    let mut d = SimpleProgramDelta::new();
    d.set_program_only(0x42);
    // Only program_only should be in specs, not both

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].offset, 6); // offset of program_only
    assert_eq!(specs[0].data, &[0x42]);
}

// --- Zero values are still included ---

#[test]
fn set_zero_value_still_included() {
    let mut d = SimpleProgramDelta::new();
    d.set_both(0);
    assert!(!d.is_empty());

    let specs = d.to_write_specs();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].offset, 4);
    assert_eq!(specs[0].data, &0u16.to_le_bytes());
}
