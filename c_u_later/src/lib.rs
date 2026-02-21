#![no_std]
//! Permission mask and type-constraint system for c_u_soon oracle auxiliary data.
//!
//! A [`CuLaterMask`] describes which bytes of the auxiliary buffer each caller
//! (program or authority) may write. [`CuLater`] combines that mask with
//! [`c_u_soon::TypeHash`], [`Pod`], and [`Zeroable`]. All four are required for a
//! type to be valid oracle auxiliary data.
//!
//! Masks are `Vec<bool>` (length = `size_of::<T>()`) where `true` = writable.
//! The on-chain wire format uses inverted encoding: `0x00` = writable, `0xFF` = blocked,
//! with trailing bytes (beyond struct size) padded to `0xFF`.
//!
//! The `#[derive(CuLater)]` macro (from [`c_u_later_derive`]) generates `CuLaterMask`
//! for a `#[repr(C)]` struct, annotating fields with `#[program]`, `#[authority]`, or
//! `#[embed]` to control per-field write permissions.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

#[cfg(feature = "derive")]
pub use c_u_later_derive::CuLater;

pub use bytemuck::{Pod, Zeroable};

#[cfg(feature = "alloc")]
pub mod validation;

pub const AUX_SIZE: usize = c_u_soon::MAX_AUX_STRUCT_SIZE;

/// Compact 256-bit permission mask (32 bytes, 1 bit per aux byte).
/// Internal to c_u_later — use `to_program_wire_mask`/`to_authority_wire_mask` for on-chain format.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct BitVec256([u8; 32]);

impl BitVec256 {
    pub(crate) const ZERO: Self = BitVec256([0; 32]);
    #[cfg(test)]
    pub(crate) const FULL: Self = BitVec256([0xFF; 32]);

    /// Marks aux byte `bit` as writable. No-op if `bit >= 256`.
    #[inline]
    pub fn set_bit(&mut self, bit: usize) {
        if bit < 256 {
            let byte = bit / 8;
            let bit_in_byte = bit % 8;
            self.0[byte] |= 1 << bit_in_byte;
        }
    }

    /// Returns `true` if aux byte `bit` is writable. Returns `false` if `bit >= 256`.
    #[inline]
    pub fn get_bit(&self, bit: usize) -> bool {
        if bit < 256 {
            let byte = bit / 8;
            let bit_in_byte = bit % 8;
            (self.0[byte] & (1 << bit_in_byte)) != 0
        } else {
            false
        }
    }

    /// Returns `true` if every byte in `offset..offset+size` is writable.
    /// Returns `false` if `offset + size > 256` or any byte in the range is blocked.
    #[inline]
    pub fn is_write_allowed(&self, offset: usize, size: usize) -> bool {
        (offset + size <= 256) && (offset..offset + size).all(|i| self.get_bit(i))
    }
}

/// Convert a bool slice mask to BitVec256 (32 bytes).
/// Only iterates `mask.len()` entries; bits beyond that stay 0 (not writable).
#[inline]
pub(crate) fn bools_to_bitvec(mask: &[bool]) -> BitVec256 {
    let mut result = BitVec256::ZERO;
    for i in 0..mask.len() {
        if mask[i] {
            result.set_bit(i);
        }
    }
    result
}

/// Get compact 256-bit program write mask for a CuLater type.
#[inline]
pub(crate) fn to_program_bitvec<T: CuLaterMask>() -> BitVec256 {
    let mask = T::program_mask();
    bools_to_bitvec(&mask)
}

/// Get compact 256-bit authority write mask for a CuLater type.
#[inline]
pub(crate) fn to_authority_bitvec<T: CuLaterMask>() -> BitVec256 {
    let mask = T::authority_mask();
    bools_to_bitvec(&mask)
}

/// Describes byte-level write permissions over the auxiliary data buffer.
///
/// Both methods return `Vec<bool>` of length `size_of::<Self>()` where `true` means
/// writable and `false` means blocked for that byte offset.
///
/// - `program_mask()`: bytes the delegated program may write.
/// - `authority_mask()`: bytes the oracle authority may write.
///
/// Primitives and fixed-size arrays of `CuLaterMask` types have built-in impls (all
/// bytes writable). Composite types derive this via `#[derive(CuLater)]`.
pub trait CuLaterMask {
    fn program_mask() -> Vec<bool>;
    fn authority_mask() -> Vec<bool>;
}

/// Marker supertrait for a complete oracle auxiliary type.
///
/// Requires [`CuLaterMask`] + [`c_u_soon::TypeHash`] + [`Pod`] + [`Zeroable`]:
/// - `CuLaterMask` enforces field-level write permissions.
/// - `TypeHash` identifies the schema on-chain; a hash mismatch causes the oracle
///   program to reject the instruction.
/// - `Pod + Zeroable` permit safe byte-level reads and zero-initialization.
///
/// Blanket impl: any type with all four bounds implements `CuLater`.
pub trait CuLater: CuLaterMask + c_u_soon::TypeHash + Pod + Zeroable {}

impl<T: CuLaterMask + c_u_soon::TypeHash + Pod + Zeroable> CuLater for T {}

#[doc(hidden)]
pub fn compose_mask_at_offset(parent: &mut Vec<bool>, child: &[bool], byte_offset: usize) {
    for i in 0..child.len() {
        if child[i] {
            let target = byte_offset + i;
            if target < parent.len() {
                parent[target] = true;
            }
        }
    }
}

macro_rules! impl_cu_later_mask_primitive {
    ($ty:ty, $size:expr) => {
        impl CuLaterMask for $ty {
            fn program_mask() -> Vec<bool> {
                vec![true; $size]
            }

            fn authority_mask() -> Vec<bool> {
                vec![true; $size]
            }
        }
    };
}

impl_cu_later_mask_primitive!(u8, 1);
impl_cu_later_mask_primitive!(u16, 2);
impl_cu_later_mask_primitive!(u32, 4);
impl_cu_later_mask_primitive!(u64, 8);
impl_cu_later_mask_primitive!(u128, 16);
impl_cu_later_mask_primitive!(i8, 1);
impl_cu_later_mask_primitive!(i16, 2);
impl_cu_later_mask_primitive!(i32, 4);
impl_cu_later_mask_primitive!(i64, 8);
impl_cu_later_mask_primitive!(i128, 16);
impl_cu_later_mask_primitive!(f32, 4);
impl_cu_later_mask_primitive!(f64, 8);
impl_cu_later_mask_primitive!(bool, 1);

impl<T: CuLaterMask, const N: usize> CuLaterMask for [T; N] {
    fn program_mask() -> Vec<bool> {
        const { assert!(N * core::mem::size_of::<T>() <= AUX_SIZE) };
        let child = T::program_mask();
        let elem_size = core::mem::size_of::<T>();
        let mut mask = vec![false; N * elem_size];
        let mut i = 0;
        while i < N {
            compose_mask_at_offset(&mut mask, &child, i * elem_size);
            i += 1;
        }
        mask
    }

    fn authority_mask() -> Vec<bool> {
        const { assert!(N * core::mem::size_of::<T>() <= AUX_SIZE) };
        let child = T::authority_mask();
        let elem_size = core::mem::size_of::<T>();
        let mut mask = vec![false; N * elem_size];
        let mut i = 0;
        while i < N {
            compose_mask_at_offset(&mut mask, &child, i * elem_size);
            i += 1;
        }
        mask
    }
}

/// Convert a CuLaterMask program mask to c_u_soon on-chain Mask format.
/// Polarity: true (writable) → 0x00, false (blocked) → 0xFF.
pub fn to_program_wire_mask<T: CuLaterMask>() -> c_u_soon::Mask {
    let mask = T::program_mask();
    bools_to_wire_mask(&mask)
}

/// Convert a CuLaterMask authority mask to c_u_soon on-chain Mask format.
/// Polarity: true (writable) → 0x00, false (blocked) → 0xFF.
pub fn to_authority_wire_mask<T: CuLaterMask>() -> c_u_soon::Mask {
    let mask = T::authority_mask();
    bools_to_wire_mask(&mask)
}

fn bools_to_wire_mask(mask: &[bool]) -> c_u_soon::Mask {
    let mut wire = [0xFFu8; c_u_soon::MASK_SIZE];
    for i in 0..mask.len().min(c_u_soon::MASK_SIZE) {
        if mask[i] {
            wire[i] = 0x00;
        }
    }
    c_u_soon::Mask::from(wire)
}

#[doc(hidden)]
pub mod __private {
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub struct IsCuLaterWrapper<T> {
    _inner: PhantomData<T>,
}

pub trait IsNotCuLater {
    fn is_cu_later() -> bool;
}

impl<T> IsNotCuLater for IsCuLaterWrapper<T> {
    fn is_cu_later() -> bool {
        false
    }
}

impl<T: CuLater> IsCuLaterWrapper<T> {
    pub fn is_cu_later() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_masks() {
        let m = u8::program_mask();
        assert_eq!(m.len(), 1);
        assert!(m[0]);

        let m = u16::program_mask();
        assert_eq!(m.len(), 2);
        for i in 0..2 {
            assert!(m[i]);
        }

        let m = u32::program_mask();
        assert_eq!(m.len(), 4);
        for i in 0..4 {
            assert!(m[i]);
        }

        let m = u64::program_mask();
        assert_eq!(m.len(), 8);
        for i in 0..8 {
            assert!(m[i]);
        }

        let m = u128::program_mask();
        assert_eq!(m.len(), 16);
        for i in 0..16 {
            assert!(m[i]);
        }
    }

    #[test]
    fn test_array_mask() {
        let mask = <[u8; 4]>::program_mask();
        assert_eq!(mask.len(), 4);
        for i in 0..4 {
            assert!(mask[i]);
        }

        let mask = <[u16; 2]>::program_mask();
        assert_eq!(mask.len(), 4);
        for i in 0..4 {
            assert!(mask[i]);
        }
    }

    #[test]
    fn test_compose_mask_at_offset() {
        let child = vec![true, true];
        let mut parent = vec![false; 8];

        compose_mask_at_offset(&mut parent, &child, 4);

        assert!(!parent[3]);
        assert!(parent[4]);
        assert!(parent[5]);
        assert!(!parent[6]);
    }

    #[test]
    fn test_array_mask_different_sizes() {
        let mask4 = <[u8; 4]>::program_mask();
        assert_eq!(mask4.len(), 4);
        for i in 0..4 {
            assert!(mask4[i], "[u8; 4] bit {} should be set", i);
        }

        let mask8 = <[u8; 8]>::program_mask();
        assert_eq!(mask8.len(), 8);
        for i in 0..8 {
            assert!(mask8[i], "[u8; 8] bit {} should be set", i);
        }

        let mask16 = <[u8; 16]>::program_mask();
        assert_eq!(mask16.len(), 16);
        for i in 0..16 {
            assert!(mask16[i], "[u8; 16] bit {} should be set", i);
        }
    }

    #[test]
    fn test_array_monomorph_mix() {
        let m4 = <[u8; 4]>::program_mask();
        let m8 = <[u8; 8]>::program_mask();
        let m16_2 = <[u16; 2]>::program_mask();

        assert_eq!(m4.len(), 4);
        for i in 0..4 {
            assert!(m4[i]);
        }

        assert_eq!(m8.len(), 8);
        for i in 0..8 {
            assert!(m8[i]);
        }

        assert_eq!(m16_2.len(), 4);
        for i in 0..4 {
            assert!(m16_2[i]);
        }
    }

    #[test]
    fn test_bitmask_set_get_bits() {
        let mut mask = BitVec256::ZERO;
        assert!(!mask.get_bit(0));
        assert!(!mask.get_bit(255));

        mask.set_bit(0);
        assert!(mask.get_bit(0));
        assert!(!mask.get_bit(1));

        mask.set_bit(255);
        assert!(mask.get_bit(255));
        assert!(mask.get_bit(0));

        mask.set_bit(256);
        assert!(!mask.get_bit(256));
    }

    #[test]
    fn test_bitmask_is_write_allowed() {
        let mut mask = BitVec256::ZERO;

        assert!(!mask.is_write_allowed(0, 1));
        assert!(!mask.is_write_allowed(0, 256));

        for i in 0..8 {
            mask.set_bit(i);
        }
        assert!(mask.is_write_allowed(0, 8));
        assert!(!mask.is_write_allowed(0, 9));
        assert!(!mask.is_write_allowed(7, 2));

        let full_mask = BitVec256::FULL;
        assert!(full_mask.is_write_allowed(0, 256));
        assert!(full_mask.is_write_allowed(100, 100));
        assert!(!full_mask.is_write_allowed(255, 2));
    }

    #[test]
    fn test_to_program_bitmask_conversion() {
        let program_mask = u8::program_mask();
        let bitmask = bools_to_bitvec(&program_mask);

        assert!(bitmask.get_bit(0));
        assert!(!bitmask.get_bit(1));
    }

    #[test]
    fn test_to_authority_bitmask_conversion() {
        let authority_mask = u16::authority_mask();
        let bitmask = bools_to_bitvec(&authority_mask);

        for i in 0..2 {
            assert!(bitmask.get_bit(i));
        }
        assert!(!bitmask.get_bit(2));
    }

    #[test]
    fn test_bitmask_roundtrip() {
        let original = u32::program_mask();
        let packed = bools_to_bitvec(&original);
        let unpacked: Vec<bool> = (0..original.len()).map(|i| packed.get_bit(i)).collect();

        assert_eq!(original, unpacked);
    }
}
