#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use bytemuck::{Pod, Zeroable};
use solana_address::Address;
use wincode::{SchemaRead, SchemaWrite};

pub const ORACLE_ACCOUNT_SIZE: usize = core::mem::size_of::<OracleState>();

// Fast path reads instruction_data_len as u8 (max 255 = u8::MAX).
// A full payload is [sequence: u64][data: ORACLE_BYTES] = 8 + 247 = 255 bytes,
// so data_size = 255, copying exactly the sequence + data fields of OracleState.
// OracleState is 256 bytes total (8 + 247 + 1 explicit pad for Pod alignment).
pub const ORACLE_BYTES: usize = 247;

pub const AUX_DATA_SIZE: usize = 128;
pub const BITMASK_SIZE: usize = AUX_DATA_SIZE;

const _: () = assert!(
    core::mem::size_of::<OracleState>() == 256,
    "OracleState must be 256 bytes (8 seq + 247 data + 1 pad)"
);

const _: () = assert!(
    core::mem::size_of::<Envelope>() == 728,
    "Envelope must be 728 bytes"
);

pub const ENVELOPE_SEED: &[u8] = b"envelope";
pub const MAX_CUSTOM_SEEDS: usize = 13;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct OracleState {
    pub sequence: u64,
    pub data: [u8; ORACLE_BYTES],
    pub _pad: [u8; 1],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Envelope {
    pub authority: Address,                     // 32  [0..32]
    pub oracle_state: OracleState,              // 256 [32..288]
    pub bump: u8,                               // 1   [288]
    pub _padding: [u8; 7],                      // 7   [289..296]
    pub delegation_authority: Address,          // 32  [296..328]
    pub program_bitmask: Bitmask,              // 128 [328..456]
    pub user_bitmask: Bitmask,                 // 128 [456..584]
    pub authority_aux_sequence: u64,           // 8   [584..592]
    pub program_aux_sequence: u64,             // 8   [592..600]
    pub auxiliary_data: [u8; AUX_DATA_SIZE],   // 128 [600..728]
}

impl Envelope {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    #[inline]
    pub fn has_delegation(&self) -> bool {
        self.delegation_authority != Address::zeroed()
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
        if byte_idx >= AUX_DATA_SIZE {
            return;
        }
        self.0[byte_idx] = 0x00;
    }

    #[inline]
    pub fn clear_bit(&mut self, byte_idx: usize) {
        if byte_idx >= AUX_DATA_SIZE {
            return;
        }
        self.0[byte_idx] = 0xFF;
    }

    #[inline]
    pub fn get_bit(&self, byte_idx: usize) -> bool {
        if byte_idx >= AUX_DATA_SIZE {
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

#[derive(Debug, Clone, SchemaWrite, SchemaRead)]
pub enum SlowPathInstruction {
    Create {
        custom_seeds: Vec<Vec<u8>>,
        bump: u8,
    },
    Close,
    SetDelegatedProgram {
        program_bitmask: [u8; BITMASK_SIZE],
        user_bitmask: [u8; BITMASK_SIZE],
    },
    ClearDelegation,
    UpdateAuxiliary {
        sequence: u64,
        data: [u8; AUX_DATA_SIZE],
    },
    UpdateAuxiliaryDelegated {
        sequence: u64,
        data: [u8; AUX_DATA_SIZE],
    },
    UpdateAuxiliaryForce {
        authority_sequence: u64,
        program_sequence: u64,
        data: [u8; AUX_DATA_SIZE],
    },
}

impl SlowPathInstruction {
    pub fn validate(&self) -> bool {
        match self {
            SlowPathInstruction::Create { custom_seeds, .. } => {
                if custom_seeds.len() > MAX_CUSTOM_SEEDS {
                    return false;
                }
                for seed in custom_seeds {
                    if seed.len() > 32 {
                        return false;
                    }
                }
                true
            }
            SlowPathInstruction::SetDelegatedProgram {
                program_bitmask,
                user_bitmask,
            } => program_bitmask
                .iter()
                .chain(user_bitmask.iter())
                .all(|&b| b == 0x00 || b == 0xFF),
            _ => true,
        }
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
    fn test_validate_rejects_non_canonical_bitmask() {
        let mut program_bitmask = [0x00u8; BITMASK_SIZE];
        program_bitmask[5] = 0x42;
        let user_bitmask = [0xFF; BITMASK_SIZE];
        let ix = SlowPathInstruction::SetDelegatedProgram {
            program_bitmask,
            user_bitmask,
        };
        assert!(!ix.validate());

        let program_bitmask = [0x00u8; BITMASK_SIZE];
        let mut user_bitmask = [0xFF; BITMASK_SIZE];
        user_bitmask[10] = 0x01;
        let ix = SlowPathInstruction::SetDelegatedProgram {
            program_bitmask,
            user_bitmask,
        };
        assert!(!ix.validate());

        let ix = SlowPathInstruction::SetDelegatedProgram {
            program_bitmask: [0x00; BITMASK_SIZE],
            user_bitmask: [0xFF; BITMASK_SIZE],
        };
        assert!(ix.validate());
    }

    #[test]
    fn test_envelope_size() {
        assert_eq!(core::mem::size_of::<Envelope>(), 728);
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
    fn test_wincode_roundtrip_create() {
        let ix = SlowPathInstruction::Create {
            custom_seeds: alloc::vec![alloc::vec![1, 2, 3], alloc::vec![4, 5]],
            bump: 42,
        };
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::Create { custom_seeds, bump } => {
                assert_eq!(bump, 42);
                assert_eq!(custom_seeds.len(), 2);
                assert_eq!(custom_seeds[0], alloc::vec![1, 2, 3]);
                assert_eq!(custom_seeds[1], alloc::vec![4, 5]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_wincode_roundtrip_update_auxiliary() {
        let data = [42u8; AUX_DATA_SIZE];
        let ix = SlowPathInstruction::UpdateAuxiliary {
            sequence: 7,
            data,
        };
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::UpdateAuxiliary {
                sequence,
                data: d,
            } => {
                assert_eq!(sequence, 7);
                assert_eq!(d, data);
            }
            _ => panic!("Wrong variant"),
        }
    }
}
