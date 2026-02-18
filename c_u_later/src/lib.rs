#![no_std]

use core::marker::PhantomData;

#[cfg(feature = "derive")]
pub use c_u_later_derive::CuLater;

pub use bytemuck::{Pod, Zeroable};

pub const AUX_SIZE: usize = 256;

pub trait CuLaterMask {
    fn program_mask() -> [bool; AUX_SIZE];
    fn authority_mask() -> [bool; AUX_SIZE];
}

pub trait CuLater: CuLaterMask + Pod + Zeroable {}

impl<T: CuLaterMask + Pod + Zeroable> CuLater for T {}

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
}
