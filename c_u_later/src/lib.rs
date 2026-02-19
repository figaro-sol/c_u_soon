#![no_std]

use core::marker::PhantomData;

#[cfg(feature = "derive")]
pub use c_u_later_derive::CuLater;

pub use bytemuck::{Pod, Zeroable};

pub mod validation;

pub const AUX_SIZE: usize = 256;

/// 256-bit permission mask: 32 bytes = 256 bits (1 byte per field in auxiliary).
/// Stored in wire format for on-chain use.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Bitmask([u8; 32]);

impl Bitmask {
    pub const ZERO: Self = Bitmask([0; 32]);
    pub const FULL: Self = Bitmask([0xFF; 32]);

    #[inline]
    pub fn set_bit(&mut self, bit: usize) {
        if bit < 256 {
            let byte = bit / 8;
            let bit_in_byte = bit % 8;
            self.0[byte] |= 1 << bit_in_byte;
        }
    }

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

    #[inline]
    pub fn is_write_allowed(&self, offset: usize, size: usize) -> bool {
        (offset + size <= 256) && (offset..offset + size).all(|i| self.get_bit(i))
    }
}

/// Convert [bool; 256] mask to Bitmask (32 bytes) for wire serialization.
#[inline]
pub fn bools_to_bitmask(mask: &[bool; AUX_SIZE]) -> Bitmask {
    let mut result = Bitmask::ZERO;
    for i in 0..256 {
        if mask[i] {
            result.set_bit(i);
        }
    }
    result
}

/// Get on-chain representation of program write mask for a CuLater type.
#[inline]
pub fn to_program_bitmask<T: CuLaterMask>() -> Bitmask {
    bools_to_bitmask(&T::program_mask())
}

/// Get on-chain representation of authority write mask for a CuLater type.
#[inline]
pub fn to_authority_bitmask<T: CuLaterMask>() -> Bitmask {
    bools_to_bitmask(&T::authority_mask())
}

pub trait CuLaterMask {
    fn program_mask() -> [bool; AUX_SIZE];
    fn authority_mask() -> [bool; AUX_SIZE];
}

pub trait CuLater: CuLaterMask + c_u_soon::TypeHash + Pod + Zeroable {}

impl<T: CuLaterMask + c_u_soon::TypeHash + Pod + Zeroable> CuLater for T {}

#[doc(hidden)]
pub fn compose_mask_at_offset(
    parent: &mut [bool; AUX_SIZE],
    child: &[bool; AUX_SIZE],
    byte_offset: usize,
) {
    for i in 0..AUX_SIZE {
        if child[i] {
            let target = byte_offset + i;
            if target < AUX_SIZE {
                parent[target] = true;
            }
        }
    }
}

macro_rules! impl_cu_later_mask_primitive {
    ($ty:ty, $size:expr) => {
        impl CuLaterMask for $ty {
            fn program_mask() -> [bool; AUX_SIZE] {
                let mut m = [false; AUX_SIZE];
                let mut i = 0;
                while i < $size {
                    m[i] = true;
                    i += 1;
                }
                m
            }

            fn authority_mask() -> [bool; AUX_SIZE] {
                Self::program_mask()
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
    fn program_mask() -> [bool; AUX_SIZE] {
        const { assert!(N * core::mem::size_of::<T>() <= AUX_SIZE) };
        let child = T::program_mask();
        let elem_size = core::mem::size_of::<T>();
        let mut mask = [false; AUX_SIZE];
        let mut i = 0;
        while i < N {
            compose_mask_at_offset(&mut mask, &child, i * elem_size);
            i += 1;
        }
        mask
    }

    fn authority_mask() -> [bool; AUX_SIZE] {
        const { assert!(N * core::mem::size_of::<T>() <= AUX_SIZE) };
        let child = T::authority_mask();
        let elem_size = core::mem::size_of::<T>();
        let mut mask = [false; AUX_SIZE];
        let mut i = 0;
        while i < N {
            compose_mask_at_offset(&mut mask, &child, i * elem_size);
            i += 1;
        }
        mask
    }
}

/// Convert a CuLaterMask program mask to c_u_soon on-chain Bitmask format.
/// Polarity: true (writable) → 0x00, false (blocked) → 0xFF.
/// Panics if any bit ≥128 is set (on-chain bitmask only covers first 128 bytes of aux_data).
pub fn to_program_wire_mask<T: CuLaterMask>() -> c_u_soon::Bitmask {
    bools_to_wire_mask(&T::program_mask())
}

/// Convert a CuLaterMask authority mask to c_u_soon on-chain Bitmask format.
/// Polarity: true (writable) → 0x00, false (blocked) → 0xFF.
/// Panics if any bit ≥128 is set (on-chain bitmask only covers first 128 bytes of aux_data).
pub fn to_authority_wire_mask<T: CuLaterMask>() -> c_u_soon::Bitmask {
    bools_to_wire_mask(&T::authority_mask())
}

fn bools_to_wire_mask(mask: &[bool; AUX_SIZE]) -> c_u_soon::Bitmask {
    for i in c_u_soon::BITMASK_SIZE..AUX_SIZE {
        assert!(
            !mask[i],
            "bit {} is set but on-chain bitmask only covers first {} bytes",
            i,
            c_u_soon::BITMASK_SIZE,
        );
    }
    let mut wire = [0xFFu8; c_u_soon::BITMASK_SIZE];
    for i in 0..c_u_soon::BITMASK_SIZE {
        if mask[i] {
            wire[i] = 0x00;
        }
    }
    c_u_soon::Bitmask::from(wire)
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
        assert!(m[0]);
        assert!(!m[1]);

        let m = u16::program_mask();
        for i in 0..2 {
            assert!(m[i]);
        }
        assert!(!m[2]);

        let m = u32::program_mask();
        for i in 0..4 {
            assert!(m[i]);
        }
        assert!(!m[4]);

        let m = u64::program_mask();
        for i in 0..8 {
            assert!(m[i]);
        }
        assert!(!m[8]);

        let m = u128::program_mask();
        for i in 0..16 {
            assert!(m[i]);
        }
        assert!(!m[16]);
    }

    #[test]
    fn test_array_mask() {
        let mask = <[u8; 4]>::program_mask();
        for i in 0..4 {
            assert!(mask[i]);
        }
        assert!(!mask[4]);

        let mask = <[u16; 2]>::program_mask();
        for i in 0..4 {
            assert!(mask[i]);
        }
        assert!(!mask[4]);
    }

    #[test]
    fn test_compose_mask_at_offset() {
        let mut child = [false; AUX_SIZE];
        child[0] = true;
        child[1] = true;
        let mut parent = [false; AUX_SIZE];

        compose_mask_at_offset(&mut parent, &child, 4);

        assert!(!parent[3]);
        assert!(parent[4]);
        assert!(parent[5]);
        assert!(!parent[6]);
    }

    #[test]
    fn test_array_mask_different_sizes() {
        let mask4 = <[u8; 4]>::program_mask();
        for i in 0..4 {
            assert!(mask4[i], "[u8; 4] bit {} should be set", i);
        }
        assert!(!mask4[4]);

        let mask8 = <[u8; 8]>::program_mask();
        for i in 0..8 {
            assert!(mask8[i], "[u8; 8] bit {} should be set", i);
        }
        assert!(!mask8[8]);

        let mask16 = <[u8; 16]>::program_mask();
        for i in 0..16 {
            assert!(mask16[i], "[u8; 16] bit {} should be set", i);
        }
        assert!(!mask16[16]);
    }

    #[test]
    fn test_array_monomorph_mix() {
        let m4 = <[u8; 4]>::program_mask();
        let m8 = <[u8; 8]>::program_mask();
        let m16_2 = <[u16; 2]>::program_mask();

        for i in 0..4 {
            assert!(m4[i]);
        }
        assert!(!m4[4]);

        for i in 0..8 {
            assert!(m8[i]);
        }
        assert!(!m8[8]);

        for i in 0..4 {
            assert!(m16_2[i]);
        }
        assert!(!m16_2[4]);
    }

    #[test]
    fn test_bitmask_set_get_bits() {
        let mut mask = Bitmask::ZERO;
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
        let mut mask = Bitmask::ZERO;

        assert!(!mask.is_write_allowed(0, 1));
        assert!(!mask.is_write_allowed(0, 256));

        for i in 0..8 {
            mask.set_bit(i);
        }
        assert!(mask.is_write_allowed(0, 8));
        assert!(!mask.is_write_allowed(0, 9));
        assert!(!mask.is_write_allowed(7, 2));

        let full_mask = Bitmask::FULL;
        assert!(full_mask.is_write_allowed(0, 256));
        assert!(full_mask.is_write_allowed(100, 100));
        assert!(!full_mask.is_write_allowed(255, 2));
    }

    #[test]
    fn test_to_program_bitmask_conversion() {
        let program_mask = u8::program_mask();
        let bitmask = bools_to_bitmask(&program_mask);

        assert!(bitmask.get_bit(0));
        assert!(!bitmask.get_bit(1));
    }

    #[test]
    fn test_to_authority_bitmask_conversion() {
        let authority_mask = u16::authority_mask();
        let bitmask = bools_to_bitmask(&authority_mask);

        for i in 0..2 {
            assert!(bitmask.get_bit(i));
        }
        assert!(!bitmask.get_bit(2));
    }

    #[test]
    fn test_bitmask_roundtrip() {
        let original = u32::program_mask();
        let packed = bools_to_bitmask(&original);
        let unpacked: [bool; 256] = core::array::from_fn(|i| packed.get_bit(i));

        assert_eq!(original, unpacked);
    }
}
