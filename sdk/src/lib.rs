#![no_std]

use bytemuck::{Pod, Zeroable};
use solana_address::Address;

pub const ORACLE_ACCOUNT_SIZE: usize = core::mem::size_of::<OracleState>();

// Fast path reads instruction_data_len as u8 (max 255 = u8::MAX).
// A full payload is [sequence: u64][data: ORACLE_BYTES] = 8 + 247 = 255 bytes,
// so data_size = 255, copying exactly the sequence + data fields of OracleState.
// OracleState is 256 bytes total (8 + 247 + 1 explicit pad for Pod alignment).
pub const ORACLE_BYTES: usize = 247;

const _: () = assert!(
    core::mem::size_of::<OracleState>() == 256,
    "OracleState must be 256 bytes (8 seq + 247 data + 1 pad)"
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
    pub authority: Address,
    pub oracle_state: OracleState,
}

impl Envelope {
    pub const SIZE: usize = core::mem::size_of::<Self>();
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
}
