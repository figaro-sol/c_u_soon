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
use c_u_soon::{AUX_DATA_SIZE, MASK_SIZE, MAX_CUSTOM_SEEDS};
use wincode::{SchemaRead, SchemaWrite};

/// Wincode serialized size: 4 (disc) + 8 (seq) + 256 (data)
pub const UPDATE_AUX_SERIALIZED_SIZE: usize = 4 + 8 + AUX_DATA_SIZE;
/// Wincode serialized size: 4 (disc) + 8 (auth_seq) + 8 (prog_seq) + 256 (data)
pub const UPDATE_AUX_FORCE_SERIALIZED_SIZE: usize = 4 + 8 + 8 + AUX_DATA_SIZE;

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
/// - `UpdateAuxiliary`: authority writes the full aux buffer. `sequence` must match
///   the oracle's current authority sequence counter.
/// - `UpdateAuxiliaryDelegated`: delegated program writes aux data. `sequence` must
///   match the oracle's current program sequence counter.
/// - `UpdateAuxiliaryForce`: authority resets both sequence counters and writes aux
///   data, bypassing the normal sequence check. Used to recover from desync.
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
    #[wincode(tag = 4)]
    UpdateAuxiliary {
        sequence: u64,
        data: [u8; AUX_DATA_SIZE],
    },
    #[wincode(tag = 5)]
    UpdateAuxiliaryDelegated {
        sequence: u64,
        data: [u8; AUX_DATA_SIZE],
    },
    #[wincode(tag = 6)]
    UpdateAuxiliaryForce {
        authority_sequence: u64,
        program_sequence: u64,
        data: [u8; AUX_DATA_SIZE],
    },
}

impl SlowPathInstruction {
    /// Returns `false` if the instruction contains invalid fields.
    ///
    /// - `Create`: rejects if `custom_seeds.len() > MAX_CUSTOM_SEEDS` or any seed is > 32 bytes.
    /// - `SetDelegatedProgram`: rejects if any byte in either bitmask is not `0x00` or `0xFF`.
    /// - All other variants always return `true`.
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
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_size_constants_match() {
        let aux = wincode::serialize(&SlowPathInstruction::UpdateAuxiliary {
            sequence: 0,
            data: [0; AUX_DATA_SIZE],
        })
        .unwrap();
        assert_eq!(
            aux.len(),
            UPDATE_AUX_SERIALIZED_SIZE,
            "UPDATE_AUX_SERIALIZED_SIZE mismatch"
        );

        let force = wincode::serialize(&SlowPathInstruction::UpdateAuxiliaryForce {
            authority_sequence: 0,
            program_sequence: 0,
            data: [0; AUX_DATA_SIZE],
        })
        .unwrap();
        assert_eq!(
            force.len(),
            UPDATE_AUX_FORCE_SERIALIZED_SIZE,
            "UPDATE_AUX_FORCE_SERIALIZED_SIZE mismatch"
        );
    }

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
                SlowPathInstruction::UpdateAuxiliary {
                    sequence: 0,
                    data: [0; AUX_DATA_SIZE],
                },
                4,
            ),
            (
                SlowPathInstruction::UpdateAuxiliaryDelegated {
                    sequence: 0,
                    data: [0; AUX_DATA_SIZE],
                },
                5,
            ),
            (
                SlowPathInstruction::UpdateAuxiliaryForce {
                    authority_sequence: 0,
                    program_sequence: 0,
                    data: [0; AUX_DATA_SIZE],
                },
                6,
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
    fn test_wincode_roundtrip_update_auxiliary() {
        let data = [42u8; AUX_DATA_SIZE];
        let ix = SlowPathInstruction::UpdateAuxiliary { sequence: 7, data };
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::UpdateAuxiliary { sequence, data: d } => {
                assert_eq!(sequence, 7);
                assert_eq!(d, data);
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

    #[test]
    fn test_wincode_roundtrip_update_auxiliary_delegated() {
        let data = [0xBBu8; AUX_DATA_SIZE];
        let ix = SlowPathInstruction::UpdateAuxiliaryDelegated { sequence: 99, data };
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::UpdateAuxiliaryDelegated { sequence, data: d } => {
                assert_eq!(sequence, 99);
                assert_eq!(d, data);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_wincode_roundtrip_update_auxiliary_force() {
        let data = [0xCCu8; AUX_DATA_SIZE];
        let ix = SlowPathInstruction::UpdateAuxiliaryForce {
            authority_sequence: 10,
            program_sequence: 20,
            data,
        };
        let serialized = wincode::serialize(&ix).unwrap();
        let deserialized: SlowPathInstruction = wincode::deserialize(&serialized).unwrap();
        match deserialized {
            SlowPathInstruction::UpdateAuxiliaryForce {
                authority_sequence,
                program_sequence,
                data: d,
            } => {
                assert_eq!(authority_sequence, 10);
                assert_eq!(program_sequence, 20);
                assert_eq!(d, data);
            }
            _ => panic!("Wrong variant"),
        }
    }
}
