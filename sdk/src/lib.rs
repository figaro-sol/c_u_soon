#![no_std]

use bytemuck::{Pod, Zeroable};
use solana_address::Address;

pub const ORACLE_ACCOUNT_SIZE: usize = core::mem::size_of::<OracleState>();

// Fast path reads instruction_data_len as u8 (max 255 = u8::MAX).
// A full payload is [oracle_meta: u64][sequence: u64][data: ORACLE_BYTES] = 8 + 8 + 239 = 255 bytes,
// so data_size = 255, copying exactly the oracle_metadata + sequence + data fields of OracleState.
// OracleState is 256 bytes total (8 + 8 + 239 + 1 explicit pad for Pod alignment).
pub const ORACLE_BYTES: usize = 239;

pub const AUX_DATA_SIZE: usize = 256;
pub const BITMASK_SIZE: usize = 256;

/// Packed oracle struct identity: bits[63:56] = type_size (u8), bits[55:0] = 56-bit hash.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct StructMetadata(pub u64);

impl StructMetadata {
    pub const ZERO: Self = Self(0);

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

// --- TypeHash: const-evaluable type identity for envelope data ---

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

pub const fn combine_hash(accumulated: u64, field_hash: u64) -> u64 {
    let rotated = accumulated.rotate_left(7) ^ field_hash;
    rotated.wrapping_mul(0x517cc1b727220a95)
}

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
    const METADATA: StructMetadata =
        StructMetadata::new((core::mem::size_of::<T>() * N) as u8, Self::TYPE_HASH);
}

#[cfg(feature = "derive")]
pub use c_u_soon_derive::TypeHash;

pub const ENVELOPE_SEED: &[u8] = b"envelope";
pub const MAX_CUSTOM_SEEDS: usize = 13;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct OracleState {
    pub oracle_metadata: StructMetadata, // 8   (Envelope[32..40])
    pub sequence: u64,
    pub data: [u8; ORACLE_BYTES],
    pub _paddingdata: [u8; 1],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Envelope {
    pub authority: Address,                  // 32  [0..32]
    pub oracle_state: OracleState,           // 256 [32..288]
    pub bump: u8,                            // 1   [288]
    pub _padding: [u8; 7],                   // 7   [289..296]
    pub delegation_authority: Address,       // 32  [296..328]
    pub program_bitmask: Bitmask,            // 256 [328..584]
    pub user_bitmask: Bitmask,               // 256 [584..840]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroable, Pod)]
#[repr(transparent)]
pub struct Bitmask(pub [u8; BITMASK_SIZE]);

impl Bitmask {
    pub const ZERO: Self = Self([0xFF; BITMASK_SIZE]);
    pub const FULL: Self = Self([0x00; BITMASK_SIZE]);

    #[inline]
    pub const fn new() -> Self {
        Self::ZERO
    }

    #[inline]
    pub const fn full() -> Self {
        Self::FULL
    }

    #[inline]
    pub fn set_bit(&mut self, byte_idx: usize) {
        if byte_idx >= BITMASK_SIZE {
            return;
        }
        self.0[byte_idx] = 0x00;
    }

    #[inline]
    pub fn clear_bit(&mut self, byte_idx: usize) {
        if byte_idx >= BITMASK_SIZE {
            return;
        }
        self.0[byte_idx] = 0xFF;
    }

    #[inline]
    pub fn get_bit(&self, byte_idx: usize) -> bool {
        if byte_idx >= BITMASK_SIZE {
            return false;
        }
        self.0[byte_idx] == 0x00
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; BITMASK_SIZE] {
        &self.0
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0 == [0xFF; BITMASK_SIZE]
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
            if !self.get_bit(byte_idx) {
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
        let mask_ptr = self.0.as_ptr() as *const u64;
        let src_ptr = src.as_ptr() as *const u64;
        let dest_ptr = dest.as_ptr() as *const u64;
        // Pass 1: validate all chunks
        for i in 0..(AUX_DATA_SIZE / 8) {
            unsafe {
                let src_qw = core::ptr::read_unaligned(src_ptr.add(i));
                let dest_qw = core::ptr::read_unaligned(dest_ptr.add(i));
                if src_qw == dest_qw {
                    continue;
                }
                let mask_qw = core::ptr::read_unaligned(mask_ptr.add(i));
                if (mask_qw & src_qw) != (mask_qw & dest_qw) {
                    return false;
                }
            }
        }
        // Pass 2: copy (blocked bytes are equal, so full copy is safe)
        dest.copy_from_slice(src);
        true
    }
}

impl Default for Bitmask {
    fn default() -> Self {
        Self::new()
    }
}

impl From<[u8; BITMASK_SIZE]> for Bitmask {
    fn from(bytes: [u8; BITMASK_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<Bitmask> for [u8; BITMASK_SIZE] {
    fn from(bitmask: Bitmask) -> Self {
        bitmask.0
    }
}

/// Parse seeds from instruction data.
/// Format: [num_seeds: u8][len: u8][data...]...[bump: u8]
pub fn parse_seeds(data: &[u8]) -> Option<(SeedParser<'_>, u8)> {
    if data.is_empty() {
        return None;
    }

    let num_seeds = data[0] as usize;
    if num_seeds > MAX_CUSTOM_SEEDS {
        return None;
    }
    let mut offset = 1;

    for _ in 0..num_seeds {
        if offset >= data.len() {
            return None;
        }
        let seed_len = data[offset] as usize;
        if seed_len > 32 {
            return None;
        }
        offset += 1;
        if offset + seed_len > data.len() {
            return None;
        }
        offset += seed_len;
    }

    if offset + 1 != data.len() {
        return None;
    }
    let bump = data[offset];

    Some((
        SeedParser {
            data,
            num_seeds,
            offset: 1,
            current: 0,
        },
        bump,
    ))
}

pub struct SeedParser<'a> {
    data: &'a [u8],
    num_seeds: usize,
    offset: usize,
    current: usize,
}

impl<'a> Iterator for SeedParser<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.num_seeds {
            return None;
        }
        let seed_len = self.data[self.offset] as usize;
        self.offset += 1;
        let seed = &self.data[self.offset..self.offset + seed_len];
        self.offset += seed_len;
        self.current += 1;
        Some(seed)
    }
}

impl SeedParser<'_> {
    pub fn len(&self) -> usize {
        self.num_seeds
    }

    pub fn is_empty(&self) -> bool {
        self.num_seeds == 0
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
    fn test_parse_seeds_empty() {
        assert!(parse_seeds(&[]).is_none());
    }

    #[test]
    fn test_parse_seeds_single() {
        let data = [1, 3, b'a', b'b', b'c', 42];
        let (mut parser, bump) = parse_seeds(&data).unwrap();
        assert_eq!(bump, 42);
        assert_eq!(parser.next(), Some(b"abc".as_slice()));
        assert_eq!(parser.next(), None);
    }

    #[test]
    fn test_parse_seeds_multiple() {
        let data = [2, 3, b'a', b'b', b'c', 4, b'd', b'e', b'f', b'g', 99];
        let (mut parser, bump) = parse_seeds(&data).unwrap();
        assert_eq!(bump, 99);
        assert_eq!(parser.len(), 2);
        assert_eq!(parser.next(), Some(b"abc".as_slice()));
        assert_eq!(parser.next(), Some(b"defg".as_slice()));
        assert_eq!(parser.next(), None);
    }

    #[test]
    fn test_parse_seeds_zero_seeds() {
        let data = [0, 1];
        let (mut parser, bump) = parse_seeds(&data).unwrap();
        assert_eq!(bump, 1);
        assert!(parser.is_empty());
        assert_eq!(parser.next(), None);
    }

    #[test]
    fn test_parse_seeds_truncated() {
        assert!(parse_seeds(&[1, 3, b'a', b'b', b'c']).is_none());
        assert!(parse_seeds(&[1, 10, b'a', b'b', b'c', 42]).is_none());
    }

    #[test]
    fn test_parse_seeds_trailing_data_rejected() {
        assert!(parse_seeds(&[1, 3, b'a', b'b', b'c', 42, 0xFF]).is_none());
        assert!(parse_seeds(&[0, 1, 0xFF, 0xFF, 0xFF]).is_none());
    }

    #[test]
    fn test_parse_seeds_seed_too_long() {
        // [num_seeds=1, len=33, 33 zero bytes, bump=42] = 36 bytes
        let mut data = [0u8; 36];
        data[0] = 1;
        data[1] = 33;
        data[35] = 42;
        assert!(parse_seeds(&data).is_none());

        // [num_seeds=1, len=32, 32 zero bytes, bump=42] = 35 bytes
        let mut data = [0u8; 35];
        data[0] = 1;
        data[1] = 32;
        data[34] = 42;
        assert!(parse_seeds(&data).is_some());
    }

    #[test]
    fn test_parse_seeds_too_many_seeds() {
        // 14 seeds of 1 byte each: [14, 1, 'x', 1, 'x', ..., 42] = 1 + 14*2 + 1 = 30
        let mut data = [0u8; 30];
        data[0] = 14;
        for i in 0..14 {
            data[1 + i * 2] = 1;
            data[2 + i * 2] = b'x';
        }
        data[29] = 42;
        assert!(parse_seeds(&data).is_none());

        // 13 seeds of 1 byte each: [13, 1, 'x', ..., 42] = 1 + 13*2 + 1 = 28
        let mut data = [0u8; 28];
        data[0] = 13;
        for i in 0..13 {
            data[1 + i * 2] = 1;
            data[2 + i * 2] = b'x';
        }
        data[27] = 42;
        assert!(parse_seeds(&data).is_some());
    }

    #[test]
    fn test_parse_seeds_empty_seed() {
        let data = [1, 0, 42];
        let (mut parser, bump) = parse_seeds(&data).unwrap();
        assert_eq!(bump, 42);
        assert_eq!(parser.next(), Some(&[][..]));
        assert_eq!(parser.next(), None);
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
        assert!(Bitmask::FULL.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[0], 0xAA);
        assert_eq!(dest[50], 0xBB);
    }

    #[test]
    fn test_bitmask_masked_update_zero_blocks() {
        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut src = [0u8; AUX_DATA_SIZE];
        src[0] = 1;
        assert!(!Bitmask::ZERO.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[0], 0);
    }

    #[test]
    fn test_bitmask_partial_update() {
        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut bitmask = Bitmask::ZERO;
        bitmask.set_bit(1);
        bitmask.set_bit(2);

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
        let mut bitmask = Bitmask::ZERO;
        assert!(!bitmask.get_bit(128));
        assert!(!bitmask.get_bit(200));
        assert!(!bitmask.get_bit(255));

        bitmask.set_bit(128);
        bitmask.set_bit(200);
        bitmask.set_bit(255);

        assert!(bitmask.get_bit(128));
        assert!(bitmask.get_bit(200));
        assert!(bitmask.get_bit(255));
        assert!(!bitmask.get_bit(127)); // adjacent untouched
        assert!(!bitmask.get_bit(129)); // adjacent untouched
    }

    #[test]
    fn test_apply_masked_update_high_offsets_writable() {
        let mut bitmask = Bitmask::ZERO;
        for i in 128..256 {
            bitmask.set_bit(i);
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
        let bitmask = Bitmask::ZERO; // all blocked

        let mut dest = [0u8; AUX_DATA_SIZE];
        let mut src = [0u8; AUX_DATA_SIZE];
        src[200] = 0xFF;

        assert!(!bitmask.apply_masked_update(&mut dest, &src));
        assert_eq!(dest[200], 0);
    }

    #[test]
    fn test_apply_masked_update_mixed_high_low() {
        let mut bitmask = Bitmask::ZERO;
        bitmask.set_bit(0);   // low writable
        bitmask.set_bit(1);   // low writable
        bitmask.set_bit(200); // high writable
        bitmask.set_bit(255); // high writable

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
