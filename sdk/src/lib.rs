#![no_std]

use bytemuck::{Pod, Zeroable};
use solana_address::Address;

pub const ORACLE_ACCOUNT_SIZE: usize = core::mem::size_of::<OracleState>();

/// Max oracle data bytes. Fast path payload = [meta:8][seq:8][data:239] = 255 = u8::MAX.
pub const ORACLE_BYTES: usize = 239;

pub const AUX_DATA_SIZE: usize = 256;
pub const MASK_SIZE: usize = 256;

/// Packed type identity for on-chain data. bits\[63:56\] = size (u8), bits\[55:0\] = FNV-1a hash.
///
/// Constructed via [`TypeHash::METADATA`] or [`StructMetadata::new`].
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct StructMetadata(u64);

impl StructMetadata {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub const fn new(type_size: u8, hash_56: u64) -> Self {
        Self(((type_size as u64) << 56) | (hash_56 & 0x00FF_FFFF_FFFF_FFFF))
    }

    pub fn type_size(&self) -> u8 {
        (self.0 >> 56) as u8
    }

    pub fn hash_56(&self) -> u64 {
        self.0 & 0x00FF_FFFF_FFFF_FFFF
    }

    pub fn of<T: TypeHash>() -> Self {
        T::METADATA
    }
}

const _: () = assert!(
    core::mem::size_of::<OracleState>() == 256,
    "OracleState must be 256 bytes (8 meta + 8 seq + 239 data + 1 pad)"
);

const _: () = assert!(
    core::mem::size_of::<Envelope>() == 1120,
    "Envelope must be 1120 bytes"
);

/// FNV-1a hash, const-evaluable. Used by [`TypeHash`] derive.
pub const fn const_fnv1a(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// Combine two hashes with rotation + multiply. Used by [`TypeHash`] derive for structs.
pub const fn combine_hash(accumulated: u64, field_hash: u64) -> u64 {
    let rotated = accumulated.rotate_left(7) ^ field_hash;
    rotated.wrapping_mul(0x517cc1b727220a95)
}

/// Const-evaluable type identity for envelope oracle/auxiliary data.
///
/// Hash is computed over the struct name and ordered field type hashes (for derived structs),
/// so structs with the same fields but different names produce different hashes.
/// Primitives and `[T; N]` arrays have built-in impls.
/// Derive with `#[derive(TypeHash)]` (requires `derive` feature).
pub trait TypeHash: Pod + Zeroable {
    const TYPE_HASH: u64;
    const METADATA: StructMetadata;
}

macro_rules! impl_type_hash_primitive {
    ($($ty:ty),*) => {$(
        impl TypeHash for $ty {
            const TYPE_HASH: u64 = const_fnv1a(stringify!($ty).as_bytes());
            const METADATA: StructMetadata = StructMetadata::new(
                core::mem::size_of::<$ty>() as u8,
                Self::TYPE_HASH,
            );
        }
    )*};
}

impl_type_hash_primitive!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64);

impl<T: TypeHash, const N: usize> TypeHash for [T; N] {
    const TYPE_HASH: u64 =
        combine_hash(combine_hash(const_fnv1a(b"array"), T::TYPE_HASH), N as u64);
    const METADATA: StructMetadata = {
        let size = core::mem::size_of::<T>() * N;
        assert!(size <= 255, "TypeHash: array size exceeds u8 max");
        StructMetadata::new(size as u8, Self::TYPE_HASH)
    };
}

#[cfg(feature = "derive")]
pub use c_u_soon_derive::TypeHash;

pub const ENVELOPE_SEED: &[u8] = b"envelope";
pub const MAX_CUSTOM_SEEDS: usize = 13;

/// Oracle data region (256 bytes). Layout: `[meta:8][seq:8][data:239][pad:1]`.
///
/// Fast path copies the first 255 bytes (meta+seq+data) directly from instruction data.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct OracleState {
    pub oracle_metadata: StructMetadata, // 8   (Envelope[32..40])
    pub sequence: u64,
    pub data: [u8; ORACLE_BYTES],
    pub _pad: [u8; 1],
}

/// On-chain envelope account (1120 bytes). Contains oracle, delegation, bitmasks, and aux data.
///
/// Field layout (byte offsets):
/// - `[0..32]`     authority
/// - `[32..288]`   oracle_state (256 bytes)
/// - `[288]`       bump
/// - `[289..296]`  padding
/// - `[296..328]`  delegation_authority (zeroed = no delegation)
/// - `[328..584]`  program_bitmask
/// - `[584..840]`  user_bitmask
/// - `[840..848]`  authority_aux_sequence
/// - `[848..856]`  program_aux_sequence
/// - `[856..864]`  auxiliary_metadata
/// - `[864..1120]` auxiliary_data
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Envelope {
    pub authority: Address,                  // 32  [0..32]
    pub oracle_state: OracleState,           // 256 [32..288]
    pub bump: u8,                            // 1   [288]
    pub _padding: [u8; 7],                   // 7   [289..296]
    pub delegation_authority: Address,       // 32  [296..328]
    pub program_bitmask: Mask,               // 256 [328..584]
    pub user_bitmask: Mask,                  // 256 [584..840]
    pub authority_aux_sequence: u64,         // 8   [840..848]
    pub program_aux_sequence: u64,           // 8   [848..856]
    pub auxiliary_metadata: StructMetadata,  // 8   [856..864]
    pub auxiliary_data: [u8; AUX_DATA_SIZE], // 256 [864..1120]
}

impl Envelope {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    #[inline]
    pub fn has_delegation(&self) -> bool {
        self.delegation_authority != Address::zeroed()
    }

    pub fn oracle<T: TypeHash>(&self) -> Option<&T> {
        let size = core::mem::size_of::<T>();
        if size > ORACLE_BYTES {
            return None;
        }
        if self.oracle_state.oracle_metadata != T::METADATA {
            return None;
        }
        bytemuck::try_from_bytes(&self.oracle_state.data[..size]).ok()
    }

    pub fn oracle_mut<T: TypeHash>(&mut self) -> Option<&mut T> {
        let size = core::mem::size_of::<T>();
        if size > ORACLE_BYTES {
            return None;
        }
        if self.oracle_state.oracle_metadata != T::METADATA {
            return None;
        }
        bytemuck::try_from_bytes_mut(&mut self.oracle_state.data[..size]).ok()
    }

    pub fn aux<T: TypeHash>(&self) -> Option<&T> {
        let size = core::mem::size_of::<T>();
        if size > AUX_DATA_SIZE {
            return None;
        }
        if self.auxiliary_metadata != T::METADATA {
            return None;
        }
        bytemuck::try_from_bytes(&self.auxiliary_data[..size]).ok()
    }

    pub fn aux_mut<T: TypeHash>(&mut self) -> Option<&mut T> {
        let size = core::mem::size_of::<T>();
        if size > AUX_DATA_SIZE {
            return None;
        }
        if self.auxiliary_metadata != T::METADATA {
            return None;
        }
        bytemuck::try_from_bytes_mut(&mut self.auxiliary_data[..size]).ok()
    }
}

/// Per-byte access control mask for auxiliary data (256 bytes).
///
/// Storage polarity: `0x00` = writable, `0xFF` = blocked. Only canonical values
/// (`0x00`/`0xFF`) are accepted on-chain.
///
/// - [`Mask::ALL_BLOCKED`] — all blocked (default for new envelopes)
/// - [`Mask::ALL_WRITABLE`] — all writable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
#[repr(transparent)]
pub struct Mask([u8; MASK_SIZE]);

impl Mask {
    /// All blocked (0xFF). Default for new envelopes.
    pub const ALL_BLOCKED: Self = Self([0xFF; MASK_SIZE]);
    /// All writable (0x00).
    pub const ALL_WRITABLE: Self = Self([0x00; MASK_SIZE]);

    /// Mark byte at `byte_idx` as writable (0x00).
    #[inline]
    pub fn allow(&mut self, byte_idx: usize) {
        if byte_idx >= MASK_SIZE {
            return;
        }
        self.0[byte_idx] = 0x00;
    }

    /// Mark byte at `byte_idx` as blocked (0xFF).
    #[inline]
    pub fn block(&mut self, byte_idx: usize) {
        if byte_idx >= MASK_SIZE {
            return;
        }
        self.0[byte_idx] = 0xFF;
    }

    /// Returns `true` if byte at `byte_idx` is writable.
    #[inline]
    pub fn is_writable(&self, byte_idx: usize) -> bool {
        if byte_idx >= MASK_SIZE {
            return false;
        }
        self.0[byte_idx] == 0x00
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; MASK_SIZE] {
        &self.0
    }

    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; MASK_SIZE] {
        &mut self.0
    }

    /// Returns `true` if all bytes are blocked.
    #[inline]
    pub fn is_all_blocked(&self) -> bool {
        self.0 == [0xFF; MASK_SIZE]
    }

    #[inline]
    pub fn is_write_allowed(&self, offset: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let end = match offset.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        if end > AUX_DATA_SIZE {
            return false;
        }
        for byte_idx in offset..end {
            if !self.is_writable(byte_idx) {
                return false;
            }
        }
        true
    }

    /// Apply a masked update: copy bytes from `src` to `dest` where the mask allows.
    ///
    /// Returns `true` if the update was fully applied (all requested changes were permitted).
    /// Returns `false` if any requested change was blocked by the mask.
    ///
    /// Storage polarity: 0xFF = blocked, 0x00 = writable.
    /// Uses u64 chunks: `(mask & src) != (mask & dest)` means blocked bytes differ -> reject.
    #[inline]
    pub fn apply_masked_update(
        &self,
        dest: &mut [u8; AUX_DATA_SIZE],
        src: &[u8; AUX_DATA_SIZE],
    ) -> bool {
        // Pass 1: validate all 8-byte chunks
        for i in 0..(AUX_DATA_SIZE / 8) {
            let off = i * 8;
            let src_qw = u64::from_ne_bytes(src[off..off + 8].try_into().unwrap());
            let dest_qw = u64::from_ne_bytes(dest[off..off + 8].try_into().unwrap());
            if src_qw == dest_qw {
                continue;
            }
            let mask_qw = u64::from_ne_bytes(self.0[off..off + 8].try_into().unwrap());
            if (mask_qw & src_qw) != (mask_qw & dest_qw) {
                return false;
            }
        }
        // Pass 2: copy (blocked bytes are equal, so full copy is safe)
        dest.copy_from_slice(src);
        true
    }
}

impl Default for Mask {
    fn default() -> Self {
        Self::ALL_BLOCKED
    }
}

impl From<[u8; MASK_SIZE]> for Mask {
    fn from(bytes: [u8; MASK_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<Mask> for [u8; MASK_SIZE] {
    fn from(mask: Mask) -> Self {
        mask.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_hash_primitives_all_distinct() {
        let hashes = [
            u8::TYPE_HASH,
            u16::TYPE_HASH,
            u32::TYPE_HASH,
            u64::TYPE_HASH,
            u128::TYPE_HASH,
            i8::TYPE_HASH,
            i16::TYPE_HASH,
            i32::TYPE_HASH,
            i64::TYPE_HASH,
            i128::TYPE_HASH,
            f32::TYPE_HASH,
            f64::TYPE_HASH,
        ];
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "hash collision at ({}, {})", i, j);
            }
        }
    }

    #[test]
    fn test_combine_hash_order_sensitive() {
        let a = const_fnv1a(b"alpha");
        let b = const_fnv1a(b"beta");
        assert_ne!(combine_hash(a, b), combine_hash(b, a));
    }

    #[test]
    fn test_array_hashes_distinct_by_element_type() {
        assert_ne!(<[u8; 4]>::TYPE_HASH, <[u32; 1]>::TYPE_HASH);
        assert_ne!(<[u8; 2]>::TYPE_HASH, <[u16; 1]>::TYPE_HASH);
    }

    #[test]
    fn test_array_hashes_distinct_by_length() {
        assert_ne!(<[u8; 4]>::TYPE_HASH, <[u8; 8]>::TYPE_HASH);
        assert_ne!(<[u32; 2]>::TYPE_HASH, <[u32; 3]>::TYPE_HASH);
    }

    #[test]
    fn test_metadata_type_size_matches() {
        assert_eq!(u8::METADATA.type_size(), 1);
        assert_eq!(u16::METADATA.type_size(), 2);
        assert_eq!(u32::METADATA.type_size(), 4);
        assert_eq!(u64::METADATA.type_size(), 8);
        assert_eq!(u128::METADATA.type_size(), 16);
        assert_eq!(<[u8; 10]>::METADATA.type_size(), 10);
        assert_eq!(<[u32; 4]>::METADATA.type_size(), 16);
    }

    #[test]
    fn test_struct_metadata_of() {
        assert_eq!(StructMetadata::of::<u32>(), u32::METADATA);
        assert_eq!(StructMetadata::of::<[u8; 4]>(), <[u8; 4]>::METADATA);
    }

    #[test]
    fn test_envelope_size() {
        assert_eq!(core::mem::size_of::<Envelope>(), 1120);
    }

    #[test]
    fn test_bitmask_masked_update_full() {
        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut src = [0u8; AUX_DATA_SIZE];
        src[0] = 0xAA;
        src[50] = 0xBB;
        assert!(Mask::ALL_WRITABLE.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[0], 0xAA);
        assert_eq!(dest[50], 0xBB);
    }

    #[test]
    fn test_bitmask_masked_update_zero_blocks() {
        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut src = [0u8; AUX_DATA_SIZE];
        src[0] = 1;
        assert!(!Mask::ALL_BLOCKED.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[0], 0);
    }

    #[test]
    fn test_bitmask_partial_update() {
        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut bitmask = Mask::ALL_BLOCKED;
        bitmask.allow(1);
        bitmask.allow(2);

        let mut src = [0u8; AUX_DATA_SIZE];
        src[1] = 0xAA;
        src[2] = 0xBB;

        assert!(bitmask.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[0], 0);
        assert_eq!(dest[1], 0xAA);
        assert_eq!(dest[2], 0xBB);
    }

    #[test]
    fn test_envelope_oracle_typed_roundtrip() {
        let mut env = Envelope::zeroed();
        env.oracle_state.oracle_metadata = u32::METADATA;
        let val: &u32 = env.oracle::<u32>().unwrap();
        assert_eq!(*val, 0);

        *env.oracle_mut::<u32>().unwrap() = 0xDEAD_BEEF;
        assert_eq!(*env.oracle::<u32>().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_envelope_oracle_wrong_metadata() {
        let mut env = Envelope::zeroed();
        env.oracle_state.oracle_metadata = u32::METADATA;
        assert!(env.oracle::<u64>().is_none());
    }

    #[test]
    fn test_envelope_aux_typed_roundtrip() {
        let mut env = Envelope::zeroed();
        env.auxiliary_metadata = <[u8; 16]>::METADATA;
        let val: &[u8; 16] = env.aux::<[u8; 16]>().unwrap();
        assert_eq!(*val, [0u8; 16]);

        let slot = env.aux_mut::<[u8; 16]>().unwrap();
        slot[0] = 0xAA;
        slot[15] = 0xBB;
        let val = env.aux::<[u8; 16]>().unwrap();
        assert_eq!(val[0], 0xAA);
        assert_eq!(val[15], 0xBB);
    }

    #[test]
    fn test_envelope_aux_wrong_metadata() {
        let mut env = Envelope::zeroed();
        env.auxiliary_metadata = u32::METADATA;
        assert!(env.aux::<u64>().is_none());
    }

    #[test]
    fn test_envelope_aux_zero_metadata_rejects() {
        let env = Envelope::zeroed();
        assert!(env.aux::<u32>().is_none());
    }

    #[test]
    fn test_bitmask_high_offset_set_get() {
        let mut bitmask = Mask::ALL_BLOCKED;
        assert!(!bitmask.is_writable(128));
        assert!(!bitmask.is_writable(200));
        assert!(!bitmask.is_writable(255));

        bitmask.allow(128);
        bitmask.allow(200);
        bitmask.allow(255);

        assert!(bitmask.is_writable(128));
        assert!(bitmask.is_writable(200));
        assert!(bitmask.is_writable(255));
        assert!(!bitmask.is_writable(127)); // adjacent untouched
        assert!(!bitmask.is_writable(129)); // adjacent untouched
    }

    #[test]
    fn test_apply_masked_update_high_offsets_writable() {
        let mut bitmask = Mask::ALL_BLOCKED;
        for i in 128..256 {
            bitmask.allow(i);
        }

        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut src = [0u8; AUX_DATA_SIZE];
        src[128] = 0xAA;
        src[200] = 0xBB;
        src[255] = 0xCC;

        assert!(bitmask.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[128], 0xAA);
        assert_eq!(dest[200], 0xBB);
        assert_eq!(dest[255], 0xCC);
    }

    #[test]
    fn test_apply_masked_update_high_offsets_blocked() {
        let bitmask = Mask::ALL_BLOCKED; // all blocked

        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut src = [0u8; AUX_DATA_SIZE];
        src[200] = 0xFF;

        assert!(!bitmask.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[200], 0);
    }

    #[test]
    fn test_apply_masked_update_mixed_high_low() {
        let mut bitmask = Mask::ALL_BLOCKED;
        bitmask.allow(0); // low writable
        bitmask.allow(1); // low writable
        bitmask.allow(200); // high writable
        bitmask.allow(255); // high writable

        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut src = [0u8; AUX_DATA_SIZE];
        src[0] = 0x11;
        src[1] = 0x22;
        src[200] = 0x33;
        src[255] = 0x44;

        assert!(bitmask.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[0], 0x11);
        assert_eq!(dest[1], 0x22);
        assert_eq!(dest[200], 0x33);
        assert_eq!(dest[255], 0x44);

        // Now try writing to a blocked byte
        let mut src2 = dest;
        src2[2] = 0xFF; // blocked
        assert!(!bitmask.apply_masked_update(&mut dest, &src2));
    }
}
