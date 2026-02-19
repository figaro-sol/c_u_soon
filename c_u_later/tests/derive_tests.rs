use bytemuck::{Pod, Zeroable};
use c_u_later::{CuLater, CuLaterMask, IsCuLaterWrapper, IsNotCuLater};
use c_u_soon::TypeHash;

#[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug, PartialEq)]
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

#[test]
fn test_simple_struct_masks() {
    let program_mask = Simple::program_mask();
    let authority_mask = Simple::authority_mask();

    for i in 0..4 {
        assert!(!program_mask[i], "program should not write byte {}", i);
        assert!(!authority_mask[i], "authority should not write byte {}", i);
    }

    for i in 4..6 {
        assert!(program_mask[i], "program should write byte {}", i);
        assert!(authority_mask[i], "authority should write byte {}", i);
    }

    assert!(program_mask[6], "program should write byte 6");
    assert!(!authority_mask[6], "authority should not write byte 6");

    assert!(!program_mask[7], "program should not write byte 7");
    assert!(authority_mask[7], "authority should write byte 7");
}

#[test]
fn test_array_field() {
    #[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
    #[repr(C)]
    struct WithArray {
        header: u32,
        #[program]
        data: [u8; 8],
        footer: u32,
    }

    let program_mask = WithArray::program_mask();

    for i in 0..4 {
        assert!(!program_mask[i], "header byte {} should be constant", i);
    }

    for i in 4..12 {
        assert!(program_mask[i], "data byte {} should be writable", i);
    }

    for i in 12..16 {
        assert!(!program_mask[i], "footer byte {} should be constant", i);
    }
}

#[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
#[repr(C)]
struct Inner {
    #[program]
    prog_field: u16,
    #[authority]
    auth_field: u16,
}

#[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
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

#[test]
fn test_nested_struct_composition() {
    let program_mask = Outer::program_mask();
    let authority_mask = Outer::authority_mask();

    for i in 0..4 {
        assert!(
            !program_mask[i],
            "header byte {} should be constant for program",
            i
        );
        assert!(
            !authority_mask[i],
            "header byte {} should be constant for authority",
            i
        );
    }

    assert!(
        program_mask[4],
        "inner_prog byte 0 should be program-writable"
    );
    assert!(
        program_mask[5],
        "inner_prog byte 1 should be program-writable"
    );
    assert!(
        !program_mask[6],
        "inner_prog byte 2 should NOT be program-writable"
    );
    assert!(
        !program_mask[7],
        "inner_prog byte 3 should NOT be program-writable"
    );

    for i in 4..8 {
        assert!(
            !authority_mask[i],
            "inner_prog byte {} should not be authority-writable",
            i
        );
    }

    for i in 8..12 {
        assert!(
            !program_mask[i],
            "inner_auth byte {} should not be program-writable",
            i
        );
    }
    assert!(
        !authority_mask[8],
        "inner_auth byte 0 should NOT be authority-writable"
    );
    assert!(
        !authority_mask[9],
        "inner_auth byte 1 should NOT be authority-writable"
    );
    assert!(
        authority_mask[10],
        "inner_auth byte 2 should be authority-writable"
    );
    assert!(
        authority_mask[11],
        "inner_auth byte 3 should be authority-writable"
    );

    assert!(
        program_mask[12],
        "inner_both byte 0 should be program-writable"
    );
    assert!(
        program_mask[13],
        "inner_both byte 1 should be program-writable"
    );
    assert!(
        !program_mask[14],
        "inner_both byte 2 should NOT be program-writable"
    );
    assert!(
        !program_mask[15],
        "inner_both byte 3 should NOT be program-writable"
    );

    assert!(
        !authority_mask[12],
        "inner_both byte 0 should NOT be authority-writable"
    );
    assert!(
        !authority_mask[13],
        "inner_both byte 1 should NOT be authority-writable"
    );
    assert!(
        authority_mask[14],
        "inner_both byte 2 should be authority-writable"
    );
    assert!(
        authority_mask[15],
        "inner_both byte 3 should be authority-writable"
    );
}

#[test]
fn detects_is_cu_later() {
    struct NotCuLater;

    #[derive(Pod, Zeroable, CuLater, Clone, Copy)]
    #[repr(C)]
    struct IsCuLater {
        x: u8,
    }

    assert!(!IsCuLaterWrapper::<NotCuLater>::is_cu_later());
    assert!(IsCuLaterWrapper::<IsCuLater>::is_cu_later());
}

#[test]
fn embed_non_cu_later_type() {
    #[derive(Pod, Zeroable, TypeHash, Copy, Clone)]
    #[repr(C)]
    struct Rational {
        numerator: u16,
        denominator: u16,
    }

    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct WithEmbed {
        #[program]
        #[embed]
        ratio: Rational,
        other: u32,
    }

    let mask = WithEmbed::program_mask();
    for i in 0..4 {
        assert!(mask[i], "byte {} should be writable", i);
    }
    for i in 4..8 {
        assert!(!mask[i], "byte {} should not be writable", i);
    }
}

#[test]
fn embed_array_of_non_cu_later() {
    #[derive(Pod, Zeroable, TypeHash, Copy, Clone)]
    #[repr(C)]
    struct Rational {
        numerator: u16,
        denominator: u16,
    }

    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct WithEmbedArray {
        #[authority]
        #[embed]
        ratios: [Rational; 2],
    }

    let mask = WithEmbedArray::authority_mask();
    for i in 0..8 {
        assert!(mask[i], "byte {} should be writable", i);
    }
}

#[test]
fn test_repr_c_with_align() {
    #[derive(Clone, Copy, Pod, Zeroable, CuLater)]
    #[repr(C, align(8))]
    struct Aligned {
        #[program]
        data: u32,
        #[authority]
        config: u32,
    }

    let program_mask = Aligned::program_mask();
    let authority_mask = Aligned::authority_mask();

    for i in 0..4 {
        assert!(
            program_mask[i],
            "data byte {} should be program-writable",
            i
        );
        assert!(
            !authority_mask[i],
            "data byte {} should not be authority-writable",
            i
        );
    }
    for i in 4..8 {
        assert!(
            !program_mask[i],
            "config byte {} should not be program-writable",
            i
        );
        assert!(
            authority_mask[i],
            "config byte {} should be authority-writable",
            i
        );
    }
}

#[test]
#[should_panic(expected = "implements CuLater")]
fn embed_rejects_cu_later_type() {
    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct InnerCuLater {
        #[program]
        x: u8,
    }

    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct OuterWithBadEmbed {
        #[program]
        #[embed]
        inner: InnerCuLater,
    }

    let _ = OuterWithBadEmbed::program_mask();
}

#[test]
#[should_panic(expected = "implements CuLater")]
fn embed_rejects_array_of_cu_later() {
    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct InnerCuLater {
        #[program]
        x: u8,
    }

    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct OuterWithBadArrayEmbed {
        #[program]
        #[embed]
        inners: [InnerCuLater; 2],
    }

    let _ = OuterWithBadArrayEmbed::program_mask();
}

#[test]
fn test_inter_field_padding() {
    #[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
    #[repr(C)]
    struct InterFieldPad {
        #[program]
        a: u8,
        _p1: u8,
        _p2: u8,
        _p3: u8,
        _p4: u8,
        _p5: u8,
        _p6: u8,
        _p7: u8,
        #[program]
        b: u64,
    }

    assert_eq!(core::mem::size_of::<InterFieldPad>(), 16);
    assert_eq!(core::mem::offset_of!(InterFieldPad, a), 0);
    assert_eq!(core::mem::offset_of!(InterFieldPad, b), 8);

    let program_mask = InterFieldPad::program_mask();

    assert!(program_mask[0], "byte 0 (field a) should be writable");

    for i in 1..8 {
        assert!(
            !program_mask[i],
            "byte {} (padding) should NOT be writable",
            i
        );
    }

    for i in 8..16 {
        assert!(program_mask[i], "byte {} (field b) should be writable", i);
    }
}

#[test]
fn test_tail_padding() {
    #[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
    #[repr(C)]
    struct TailPad {
        #[program]
        big: u64,
        #[authority]
        small: u8,
        _p1: u8,
        _p2: u8,
        _p3: u8,
        _p4: u8,
        _p5: u8,
        _p6: u8,
        _p7: u8,
    }

    assert_eq!(core::mem::size_of::<TailPad>(), 16);
    assert_eq!(core::mem::offset_of!(TailPad, big), 0);
    assert_eq!(core::mem::offset_of!(TailPad, small), 8);

    let program_mask = TailPad::program_mask();
    let authority_mask = TailPad::authority_mask();

    for i in 0..8 {
        assert!(
            program_mask[i],
            "byte {} (field big) should be program-writable",
            i
        );
        assert!(
            !authority_mask[i],
            "byte {} (field big) should NOT be authority-writable",
            i
        );
    }

    assert!(
        !program_mask[8],
        "byte 8 (field small) should NOT be program-writable"
    );
    assert!(
        authority_mask[8],
        "byte 8 (field small) should be authority-writable"
    );

    for i in 9..16 {
        assert!(
            !program_mask[i],
            "byte {} (tail padding) should NOT be program-writable",
            i
        );
        assert!(
            !authority_mask[i],
            "byte {} (tail padding) should NOT be authority-writable",
            i
        );
    }
}

#[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
#[repr(C)]
struct InnerPadded {
    #[program]
    x: u8,
    _pad: u8,
    #[program]
    y: u16,
}

#[test]
fn test_nested_struct_with_internal_padding() {
    assert_eq!(core::mem::size_of::<InnerPadded>(), 4);
    assert_eq!(core::mem::offset_of!(InnerPadded, x), 0);
    assert_eq!(core::mem::offset_of!(InnerPadded, _pad), 1);
    assert_eq!(core::mem::offset_of!(InnerPadded, y), 2);

    let inner_mask = InnerPadded::program_mask();
    assert!(inner_mask[0], "inner byte 0 (x) should be writable");
    assert!(
        !inner_mask[1],
        "inner byte 1 (padding) should NOT be writable"
    );
    assert!(inner_mask[2], "inner byte 2 (y low) should be writable");
    assert!(inner_mask[3], "inner byte 3 (y high) should be writable");

    #[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
    #[repr(C)]
    struct OuterWithPaddedInner {
        header: u32,
        #[program]
        inner: InnerPadded,
    }

    assert_eq!(core::mem::size_of::<OuterWithPaddedInner>(), 8);
    assert_eq!(core::mem::offset_of!(OuterWithPaddedInner, header), 0);
    assert_eq!(core::mem::offset_of!(OuterWithPaddedInner, inner), 4);

    let outer_mask = OuterWithPaddedInner::program_mask();

    for i in 0..4 {
        assert!(!outer_mask[i], "byte {} (header) should NOT be writable", i);
    }

    assert!(outer_mask[4], "byte 4 (inner.x) should be writable");
    assert!(
        !outer_mask[5],
        "byte 5 (inner padding) should NOT be writable"
    );
    assert!(outer_mask[6], "byte 6 (inner.y low) should be writable");
    assert!(outer_mask[7], "byte 7 (inner.y high) should be writable");
}

#[test]
fn test_repeated_padded_structs() {
    #[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
    #[repr(C)]
    struct WithPaddedArray {
        #[program]
        elements: [InnerPadded; 3],
    }

    assert_eq!(core::mem::size_of::<WithPaddedArray>(), 12);

    let mask = WithPaddedArray::program_mask();

    for elem in 0..3usize {
        let base = elem * 4;

        assert!(mask[base], "element {} byte 0 (x) should be writable", elem);
        assert!(
            !mask[base + 1],
            "element {} byte 1 (padding) should NOT be writable",
            elem
        );
        assert!(
            mask[base + 2],
            "element {} byte 2 (y low) should be writable",
            elem
        );
        assert!(
            mask[base + 3],
            "element {} byte 3 (y high) should be writable",
            elem
        );
    }
}

#[test]
fn test_array_monomorph_independence() {
    let m4 = <[u8; 4]>::program_mask();
    let m8 = <[u8; 8]>::program_mask();
    let m16_2 = <[u16; 2]>::program_mask();

    for i in 0..4 {
        assert!(m4[i], "[u8; 4] bit {}", i);
    }
    assert!(!m4[4]);

    for i in 0..8 {
        assert!(m8[i], "[u8; 8] bit {}", i);
    }
    assert!(!m8[8]);

    for i in 0..4 {
        assert!(m16_2[i], "[u16; 2] bit {}", i);
    }
    assert!(!m16_2[4]);
}

#[test]
fn test_nested_arrays() {
    let mask = <[[u16; 2]; 2]>::program_mask();
    for i in 0..8 {
        assert!(mask[i], "bit {} should be set", i);
    }
    assert!(!mask[8]);
}

#[test]
fn test_128_byte_struct() {
    #[derive(Clone, Copy, Pod, Zeroable, CuLater, Debug)]
    #[repr(C)]
    struct Boundary128 {
        #[program]
        p0: u64,
        #[program]
        p1: u64,
        #[program]
        p2: u64,
        #[program]
        p3: u64,
        #[program]
        p4: u64,
        #[program]
        p5: u64,
        #[program]
        p6: u64,
        #[program]
        p7: u64,
        #[authority]
        a0: u64,
        #[authority]
        a1: u64,
        #[authority]
        a2: u64,
        #[authority]
        a3: u64,
        #[authority]
        a4: u64,
        #[authority]
        a5: u64,
        #[authority]
        a6: u64,
        readonly: u8,
        _p1: u8,
        _p2: u8,
        _p3: u8,
        _p4: u8,
        _p5: u8,
        _p6: u8,
        _p7: u8,
    }

    assert_eq!(core::mem::size_of::<Boundary128>(), 128);

    let program_mask = Boundary128::program_mask();
    let authority_mask = Boundary128::authority_mask();

    for i in 0..64 {
        assert!(program_mask[i], "byte {} should be program-writable", i);
        assert!(
            !authority_mask[i],
            "byte {} should NOT be authority-writable",
            i
        );
    }

    for i in 64..120 {
        assert!(
            !program_mask[i],
            "byte {} should NOT be program-writable",
            i
        );
        assert!(authority_mask[i], "byte {} should be authority-writable", i);
    }

    assert!(
        !program_mask[120],
        "byte 120 (readonly) should NOT be program-writable"
    );
    assert!(
        !authority_mask[120],
        "byte 120 (readonly) should NOT be authority-writable"
    );

    for i in 121..128 {
        assert!(
            !program_mask[i],
            "byte {} (tail padding) should NOT be program-writable",
            i
        );
        assert!(
            !authority_mask[i],
            "byte {} (tail padding) should NOT be authority-writable",
            i
        );
    }
}

#[test]
fn embed_with_program_and_authority() {
    #[derive(Pod, Zeroable, TypeHash, Copy, Clone)]
    #[repr(C)]
    struct Pair {
        a: u16,
        b: u16,
    }

    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct WithFullEmbed {
        #[program]
        #[authority]
        #[embed]
        pair: Pair,
        other: u32,
    }

    let program_mask = WithFullEmbed::program_mask();
    let authority_mask = WithFullEmbed::authority_mask();

    for i in 0..4 {
        assert!(program_mask[i], "byte {} should be program-writable", i);
        assert!(authority_mask[i], "byte {} should be authority-writable", i);
    }
    for i in 4..8 {
        assert!(
            !program_mask[i],
            "byte {} should not be program-writable",
            i
        );
        assert!(
            !authority_mask[i],
            "byte {} should not be authority-writable",
            i
        );
    }
}

#[test]
#[should_panic(expected = "implements CuLater")]
fn embed_rejects_cu_later_type_via_authority() {
    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct InnerCuLater {
        #[program]
        x: u8,
    }

    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct OuterWithBadEmbed {
        #[authority]
        #[embed]
        inner: InnerCuLater,
    }

    let _ = OuterWithBadEmbed::authority_mask();
}

// --- TypeHash integration tests ---

#[test]
fn cu_later_derive_generates_type_hash() {
    use c_u_soon::TypeHash;
    assert_eq!(
        Simple::METADATA.type_size() as usize,
        core::mem::size_of::<Simple>()
    );
    // Hash is deterministic
    assert_eq!(Simple::TYPE_HASH, Simple::TYPE_HASH);
}

#[test]
fn cu_later_type_hash_matches_standalone_derive() {
    use c_u_soon::{combine_hash, const_fnv1a, TypeHash};
    // Simple has fields: readonly: u32, both: u16, program_only: u8, authority_only: u8
    let expected = combine_hash(
        combine_hash(
            combine_hash(
                combine_hash(const_fnv1a(b"__struct_init__"), u32::TYPE_HASH),
                u16::TYPE_HASH,
            ),
            u8::TYPE_HASH,
        ),
        u8::TYPE_HASH,
    );
    assert_eq!(Simple::TYPE_HASH, expected);
}

// --- Wire mask conversion tests ---

#[test]
fn wire_mask_polarity() {
    let wire = c_u_later::to_program_wire_mask::<Simple>();
    // Simple: bytes 0-3 readonly, 4-5 writable, 6 writable, 7 not writable
    // Wire polarity: writable=0x00, blocked=0xFF
    for i in 0..4 {
        assert_eq!(wire.0[i], 0xFF, "byte {} should be blocked (0xFF)", i);
    }
    for i in 4..7 {
        assert_eq!(wire.0[i], 0x00, "byte {} should be writable (0x00)", i);
    }
}

#[test]
fn wire_mask_roundtrip_with_is_write_allowed() {
    let wire = c_u_later::to_program_wire_mask::<Simple>();
    // bytes 4-6 should be writable
    assert!(wire.is_write_allowed(4, 3));
    // byte 0 should not
    assert!(!wire.is_write_allowed(0, 1));
}

#[test]
fn wire_mask_authority() {
    let wire = c_u_later::to_authority_wire_mask::<Simple>();
    // Simple authority: bytes 4-5 (both) writable, byte 7 (authority_only) writable
    assert!(wire.is_write_allowed(4, 2));
    assert!(wire.is_write_allowed(7, 1));
    assert!(!wire.is_write_allowed(0, 1));
    assert!(!wire.is_write_allowed(6, 1));
}

#[test]
#[should_panic(expected = "on-chain bitmask only covers")]
fn wire_mask_panics_on_out_of_range() {
    #[derive(Pod, Zeroable, CuLater, Copy, Clone)]
    #[repr(C)]
    struct Big {
        #[program]
        data: [u8; 200],
        rest: [u8; 56],
    }

    let _ = c_u_later::to_program_wire_mask::<Big>();
}
