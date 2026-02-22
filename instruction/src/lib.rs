#![no_std]
//! Slow-path instruction types for the c_u_soon oracle program.
//!
//! [`SlowPathInstruction`] covers state-management operations: account creation and
//! closure, delegation configuration, and auxiliary data writes. Fast-path oracle
//! updates use a compact format handled directly by the program entry point and are
//! not represented here.
//!
//! Serialized with `wincode`: a little-endian `u32` discriminant followed by variant
//! fields. Discriminant tags are stable on-chain (see test `discriminant_stability`).

extern crate alloc;

use alloc::vec::Vec;
use c_u_soon::{MASK_SIZE, MAX_AUX_STRUCT_SIZE, MAX_CUSTOM_SEEDS};
use wincode::{SchemaRead, SchemaWrite};

/// Wire format tag for UpdateAuxiliary: `[disc:4][metadata:8][sequence:8][data:N]`
pub const UPDATE_AUX_TAG: u32 = 4;
/// Wire format tag for UpdateAuxiliaryDelegated: `[disc:4][metadata:8][sequence:8][data:N]`
pub const UPDATE_AUX_DELEGATED_TAG: u32 = 5;
/// Wire format tag for UpdateAuxiliaryForce: `[disc:4][metadata:8][auth_seq:8][prog_seq:8][data:N]`
pub const UPDATE_AUX_FORCE_TAG: u32 = 6;
/// Wire format tag for UpdateAuxiliaryRange: `[disc:4][metadata:8][sequence:8][offset:1][data:N]`
pub const UPDATE_AUX_RANGE_TAG: u32 = 7;
/// Wire format tag for UpdateAuxiliaryDelegatedRange: `[disc:4][metadata:8][sequence:8][offset:1][data:N]`
pub const UPDATE_AUX_DELEGATED_RANGE_TAG: u32 = 8;
/// Header size for UpdateAuxiliary/UpdateAuxiliaryDelegated: disc(4) + metadata(8) + sequence(8)
pub const UPDATE_AUX_HEADER_SIZE: usize = 4 + 8 + 8;
/// Header size for UpdateAuxiliaryForce: disc(4) + metadata(8) + auth_seq(8) + prog_seq(8)
pub const UPDATE_AUX_FORCE_HEADER_SIZE: usize = 4 + 8 + 8 + 8;
/// Header size for UpdateAuxiliaryRange/DelegatedRange: disc(4) + metadata(8) + sequence(8) + offset(1)
pub const UPDATE_AUX_RANGE_HEADER_SIZE: usize = 4 + 8 + 8 + 1;

/// Max serialized size for UpdateAuxiliary/Delegated: header(20) + max_data(255) = 275
pub const UPDATE_AUX_MAX_SIZE: usize = UPDATE_AUX_HEADER_SIZE + MAX_AUX_STRUCT_SIZE;
/// Max serialized size for UpdateAuxiliaryForce: header(28) + max_data(255) = 283
pub const UPDATE_AUX_FORCE_MAX_SIZE: usize = UPDATE_AUX_FORCE_HEADER_SIZE + MAX_AUX_STRUCT_SIZE;
/// Max serialized size for UpdateAuxiliaryRange/DelegatedRange: header(21) + max_data(255) = 276
pub const UPDATE_AUX_RANGE_MAX_SIZE: usize = UPDATE_AUX_RANGE_HEADER_SIZE + MAX_AUX_STRUCT_SIZE;

/// A single write operation: write `data` at byte `offset` within the auxiliary buffer.
#[derive(Debug, Clone, SchemaWrite, SchemaRead)]
pub struct WriteSpec {
    pub offset: u8,
    pub data: Vec<u8>,
}

/// Instruction enum for slow-path operations on a c_u_soon oracle account.
///
/// Write mask encoding: `0x00` = writable, `0xFF` = blocked. Only canonical values
/// (every byte is exactly `0x00` or `0xFF`) are accepted; [`validate`][Self::validate]
/// rejects anything else.
///
/// # Variants
///
/// - `Create`: initializes the oracle PDA. `custom_seeds` (≤ `MAX_CUSTOM_SEEDS`, each ≤ 32 bytes)
///   and `bump` identify the PDA address. `oracle_metadata` is the packed `StructMetadata`
///   for the oracle's auxiliary type.
/// - `Close`: deallocates the oracle account and returns lamports to the authority.
///   Blocked while delegation is active.
/// - `SetDelegatedProgram`: assigns write permissions to a delegated program.
///   `program_bitmask` limits what the delegate can write; `user_bitmask` limits what
///   the authority can write while delegation is in effect.
/// - `ClearDelegation`: removes the delegated program and zeros the oracle state.
///
/// Update variants (tags 4-6) use a manual wire format (not wincode) for
/// variable-length data; see `UPDATE_AUX_TAG`, `UPDATE_AUX_DELEGATED_TAG`,
/// `UPDATE_AUX_FORCE_TAG`.
#[derive(Debug, Clone, SchemaWrite, SchemaRead)]
pub enum SlowPathInstruction {
    #[wincode(tag = 0)]
    Create {
        custom_seeds: Vec<Vec<u8>>,
        bump: u8,
        oracle_metadata: u64,
    },
    #[wincode(tag = 1)]
    Close,
    #[wincode(tag = 2)]
    SetDelegatedProgram {
        program_bitmask: [u8; MASK_SIZE],
        user_bitmask: [u8; MASK_SIZE],
    },
    #[wincode(tag = 3)]
    ClearDelegation,
    #[wincode(tag = 9)]
    UpdateAuxiliaryMultiRange {
        metadata: u64,
        sequence: u64,
        ranges: Vec<WriteSpec>,
    },
    #[wincode(tag = 10)]
    UpdateAuxiliaryDelegatedMultiRange {
        metadata: u64,
        sequence: u64,
        ranges: Vec<WriteSpec>,
    },
}

impl SlowPathInstruction {
    /// Returns `false` if the instruction contains invalid fields.
    ///
    /// - `Create`: rejects if `custom_seeds.len() > MAX_CUSTOM_SEEDS` or any seed is > 32 bytes.
    /// - `SetDelegatedProgram`: rejects if any byte in either bitmask is not `0x00` or `0xFF`.
    /// - `Close` and `ClearDelegation` always return `true`.
    ///
    /// Account-level checks (signer authority, PDA derivation, sequence counters) are
    /// not performed here; those happen in the program handler.
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
            SlowPathInstruction::Close | SlowPathInstruction::ClearDelegation => true,
            SlowPathInstruction::UpdateAuxiliaryMultiRange { ranges, .. }
            | SlowPathInstruction::UpdateAuxiliaryDelegatedMultiRange { ranges, .. } => {
                if ranges.is_empty() || ranges.len() > MAX_AUX_STRUCT_SIZE {
                    return false;
                }
                ranges.iter().all(|spec| !spec.data.is_empty())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminant_stability() {
        let cases: &[(SlowPathInstruction, u32)] = &[
            (
                SlowPathInstruction::Create {
                    custom_seeds: alloc::vec![],
                    bump: 0,
                    oracle_metadata: 0,
                },
                0,
            ),
            (SlowPathInstruction::Close, 1),
            (
                SlowPathInstruction::SetDelegatedProgram {
                    program_bitmask: [0; MASK_SIZE],
                    user_bitmask: [0; MASK_SIZE],
                },
                2,
            ),
            (SlowPathInstruction::ClearDelegation, 3),
            (
                SlowPathInstruction::UpdateAuxiliaryMultiRange {
                    metadata: 0,
                    sequence: 0,
                    ranges: alloc::vec![WriteSpec {
                        offset: 0,
                        data: alloc::vec![0]
                    }],
                },
                9,
            ),
            (
                SlowPathInstruction::UpdateAuxiliaryDelegatedMultiRange {
                    metadata: 0,
                    sequence: 0,
                    ranges: alloc::vec![WriteSpec {
                        offset: 0,
                        data: alloc::vec![0]
                    }],
                },
                10,
            ),
        ];
        for (ix, expected_disc) in cases {
            let bytes = wincode::serialize(ix).unwrap();
            let disc = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            assert_eq!(
                disc,
                *expected_disc,
                "discriminant mismatch for {:?}",
                core::mem::discriminant(ix)
            );
        }
    }

    #[test]
    fn test_update_aux_tags_match_old_discriminants() {
        assert_eq!(UPDATE_AUX_TAG, 4);
        assert_eq!(UPDATE_AUX_DELEGATED_TAG, 5);
        assert_eq!(UPDATE_AUX_FORCE_TAG, 6);
        assert_eq!(UPDATE_AUX_RANGE_TAG, 7);
        assert_eq!(UPDATE_AUX_DELEGATED_RANGE_TAG, 8);
    }

    #[test]
    fn test_header_size_constants() {
        assert_eq!(UPDATE_AUX_HEADER_SIZE, 20);
        assert_eq!(UPDATE_AUX_FORCE_HEADER_SIZE, 28);
        assert_eq!(UPDATE_AUX_RANGE_HEADER_SIZE, 21);
        assert_eq!(UPDATE_AUX_MAX_SIZE, 275);
        assert_eq!(UPDATE_AUX_FORCE_MAX_SIZE, 283);
        assert_eq!(UPDATE_AUX_RANGE_MAX_SIZE, 276);
    }

    #[test]
    fn test_wincode_roundtrip_update_aux_multi_range() {
        let ix = SlowPathInstruction::UpdateAuxiliaryMultiRange {
            metadata: 0xDEAD_BEEF_1234_5678,
            sequence: 42,
            ranges: alloc::vec![
                WriteSpec {
                    offset: 5,
                    data: alloc::vec![0xAA; 3]
                },
                WriteSpec {
                    offset: 20,
                    data: alloc::vec![0xBB; 2]
                },
            ],
        };
        let serialized = wincode::serialize(&ix).unwrap();
        let disc = u32::from_le_bytes(serialized[..4].try_into().unwrap());
        assert_eq!(disc, 9);
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::UpdateAuxiliaryMultiRange {
                metadata,
                sequence,
                ranges,
            } => {
                assert_eq!(metadata, 0xDEAD_BEEF_1234_5678);
                assert_eq!(sequence, 42);
                assert_eq!(ranges.len(), 2);
                assert_eq!(ranges[0].offset, 5);
                assert_eq!(ranges[0].data, alloc::vec![0xAA; 3]);
                assert_eq!(ranges[1].offset, 20);
                assert_eq!(ranges[1].data, alloc::vec![0xBB; 2]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_wincode_roundtrip_update_aux_delegated_multi_range() {
        let ix = SlowPathInstruction::UpdateAuxiliaryDelegatedMultiRange {
            metadata: 0x1234,
            sequence: 99,
            ranges: alloc::vec![WriteSpec {
                offset: 0,
                data: alloc::vec![0xFF]
            },],
        };
        let serialized = wincode::serialize(&ix).unwrap();
        let disc = u32::from_le_bytes(serialized[..4].try_into().unwrap());
        assert_eq!(disc, 10);
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::UpdateAuxiliaryDelegatedMultiRange {
                metadata,
                sequence,
                ranges,
            } => {
                assert_eq!(metadata, 0x1234);
                assert_eq!(sequence, 99);
                assert_eq!(ranges.len(), 1);
                assert_eq!(ranges[0].offset, 0);
                assert_eq!(ranges[0].data, alloc::vec![0xFF]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_validate_multi_range_empty_ranges() {
        let ix = SlowPathInstruction::UpdateAuxiliaryMultiRange {
            metadata: 0,
            sequence: 1,
            ranges: alloc::vec![],
        };
        assert!(!ix.validate());
    }

    #[test]
    fn test_validate_multi_range_empty_data() {
        let ix = SlowPathInstruction::UpdateAuxiliaryMultiRange {
            metadata: 0,
            sequence: 1,
            ranges: alloc::vec![WriteSpec {
                offset: 0,
                data: alloc::vec![]
            }],
        };
        assert!(!ix.validate());
    }

    #[test]
    fn test_validate_multi_range_valid() {
        let ix = SlowPathInstruction::UpdateAuxiliaryMultiRange {
            metadata: 0,
            sequence: 1,
            ranges: alloc::vec![WriteSpec {
                offset: 0,
                data: alloc::vec![0xAA]
            }],
        };
        assert!(ix.validate());
    }

    #[test]
    fn test_manual_wire_format_update_aux() {
        let metadata: u64 = 0xDEAD_BEEF_1234_5678;
        let sequence: u64 = 42;
        let data = [0xAA; 200];

        let mut buf = alloc::vec![];
        buf.extend_from_slice(&UPDATE_AUX_TAG.to_le_bytes());
        buf.extend_from_slice(&metadata.to_le_bytes());
        buf.extend_from_slice(&sequence.to_le_bytes());
        buf.extend_from_slice(&data);

        assert_eq!(buf.len(), UPDATE_AUX_HEADER_SIZE + 200);

        let disc = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(disc, UPDATE_AUX_TAG);
        let parsed_meta = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        assert_eq!(parsed_meta, metadata);
        let parsed_seq = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        assert_eq!(parsed_seq, sequence);
        assert_eq!(&buf[20..], &data);
    }

    #[test]
    fn test_manual_wire_format_update_aux_force() {
        let metadata: u64 = 0x1234;
        let auth_seq: u64 = 10;
        let prog_seq: u64 = 20;
        let data = [0xBB; 100];

        let mut buf = alloc::vec![];
        buf.extend_from_slice(&UPDATE_AUX_FORCE_TAG.to_le_bytes());
        buf.extend_from_slice(&metadata.to_le_bytes());
        buf.extend_from_slice(&auth_seq.to_le_bytes());
        buf.extend_from_slice(&prog_seq.to_le_bytes());
        buf.extend_from_slice(&data);

        assert_eq!(buf.len(), UPDATE_AUX_FORCE_HEADER_SIZE + 100);

        let disc = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(disc, UPDATE_AUX_FORCE_TAG);
        let parsed_meta = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        assert_eq!(parsed_meta, metadata);
        let parsed_auth = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        assert_eq!(parsed_auth, auth_seq);
        let parsed_prog = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        assert_eq!(parsed_prog, prog_seq);
        assert_eq!(&buf[28..], &data);
    }

    #[test]
    fn test_manual_wire_format_update_aux_range() {
        let metadata: u64 = 0xDEAD_BEEF_1234_5678;
        let sequence: u64 = 42;
        let offset: u8 = 10;
        let data = [0xCC; 16];

        let mut buf = alloc::vec![];
        buf.extend_from_slice(&UPDATE_AUX_RANGE_TAG.to_le_bytes());
        buf.extend_from_slice(&metadata.to_le_bytes());
        buf.extend_from_slice(&sequence.to_le_bytes());
        buf.push(offset);
        buf.extend_from_slice(&data);

        assert_eq!(buf.len(), UPDATE_AUX_RANGE_HEADER_SIZE + 16);

        let disc = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(disc, UPDATE_AUX_RANGE_TAG);
        let parsed_meta = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        assert_eq!(parsed_meta, metadata);
        let parsed_seq = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        assert_eq!(parsed_seq, sequence);
        assert_eq!(buf[20], offset);
        assert_eq!(&buf[21..], &data);
    }

    #[test]
    fn test_validate_rejects_non_canonical_bitmask() {
        let mut program_bitmask = [0x00u8; MASK_SIZE];
        program_bitmask[5] = 0x42;
        let user_bitmask = [0xFF; MASK_SIZE];
        let ix = SlowPathInstruction::SetDelegatedProgram {
            program_bitmask,
            user_bitmask,
        };
        assert!(!ix.validate());

        let program_bitmask = [0x00u8; MASK_SIZE];
        let mut user_bitmask = [0xFF; MASK_SIZE];
        user_bitmask[10] = 0x01;
        let ix = SlowPathInstruction::SetDelegatedProgram {
            program_bitmask,
            user_bitmask,
        };
        assert!(!ix.validate());

        let ix = SlowPathInstruction::SetDelegatedProgram {
            program_bitmask: [0x00; MASK_SIZE],
            user_bitmask: [0xFF; MASK_SIZE],
        };
        assert!(ix.validate());
    }

    #[test]
    fn test_wincode_roundtrip_create() {
        let ix = SlowPathInstruction::Create {
            custom_seeds: alloc::vec![alloc::vec![1, 2, 3], alloc::vec![4, 5]],
            bump: 42,
            oracle_metadata: 0xDEAD_BEEF_1234_5678,
        };
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::Create {
                custom_seeds,
                bump,
                oracle_metadata,
            } => {
                assert_eq!(bump, 42);
                assert_eq!(oracle_metadata, 0xDEAD_BEEF_1234_5678);
                assert_eq!(custom_seeds.len(), 2);
                assert_eq!(custom_seeds[0], alloc::vec![1, 2, 3]);
                assert_eq!(custom_seeds[1], alloc::vec![4, 5]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_wincode_roundtrip_close() {
        let ix = SlowPathInstruction::Close;
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        assert!(matches!(deserialized, SlowPathInstruction::Close));
    }

    #[test]
    fn test_wincode_roundtrip_set_delegated_program() {
        let mut program_bitmask = [0x00u8; MASK_SIZE];
        program_bitmask[0] = 0xFF;
        program_bitmask[127] = 0xFF;
        let user_bitmask = [0xFF; MASK_SIZE];

        let ix = SlowPathInstruction::SetDelegatedProgram {
            program_bitmask,
            user_bitmask,
        };
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::SetDelegatedProgram {
                program_bitmask: pb,
                user_bitmask: ub,
            } => {
                assert_eq!(pb, program_bitmask);
                assert_eq!(ub, user_bitmask);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_wincode_roundtrip_clear_delegation() {
        let ix = SlowPathInstruction::ClearDelegation;
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        assert!(matches!(deserialized, SlowPathInstruction::ClearDelegation));
    }
}
