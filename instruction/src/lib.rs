#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use c_u_soon::{AUX_DATA_SIZE, MASK_SIZE, MAX_CUSTOM_SEEDS};
use wincode::{SchemaRead, SchemaWrite};

#[derive(Debug, Clone, SchemaWrite, SchemaRead)]
pub enum SlowPathInstruction {
    Create {
        custom_seeds: Vec<Vec<u8>>,
        bump: u8,
        oracle_metadata: u64,
    },
    Close,
    SetDelegatedProgram {
        program_bitmask: [u8; MASK_SIZE],
        user_bitmask: [u8; MASK_SIZE],
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
