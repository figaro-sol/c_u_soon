#![no_std]

use c_u_soon_cpi::{FastPathUpdate, UpdateAuxiliary, UpdateAuxiliaryDelegated, UpdateAuxiliaryForce};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Legitimate CPI caller for c_u_soon. Used to test valid multi-program CPI paths.
/// Format: [discriminant: u8][fields...]
///
/// 0x00: UpdateViaFastPath   [oracle_meta: u64 LE][seq: u64 LE][payload_len: u8][payload bytes]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=c_u_soon_program
///
/// 0x01: UpdateViaSlowPath   [metadata: u64 LE][seq: u64 LE][data: rest]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=pda(signer), [3]=c_u_soon_program
///
/// 0x02: UpdateViaDelegated  [metadata: u64 LE][seq: u64 LE][data: rest]
///   Accounts: [0]=delegation_auth(signer), [1]=envelope(writable), [2]=padding, [3]=c_u_soon_program
///
/// 0x03: UpdateViaForce      [metadata: u64 LE][auth_seq: u64 LE][prog_seq: u64 LE][data: rest]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=delegation_auth(signer), [3]=c_u_soon_program
///
/// 0x04: Echo

pinocchio::program_entrypoint!(process_instruction);
pinocchio::default_allocator!();
pinocchio::nostd_panic_handler!();

pub fn process_instruction(
    _program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    match instruction_data[0] {
        0x00 => {
            if accounts.len() < 3 || instruction_data.len() < 18 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let oracle_meta = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let payload_len = instruction_data[17] as usize;
            if instruction_data.len() < 18 + payload_len {
                return Err(ProgramError::InvalidInstructionData);
            }
            let payload = &instruction_data[18..18 + payload_len];
            FastPathUpdate {
                authority: &accounts[0],
                envelope: &accounts[1],
                program: &accounts[2],
                oracle_meta,
                sequence,
                payload,
            }
            .invoke()
        }
        0x01 => {
            // [metadata:8][seq:8][data:rest]
            if accounts.len() < 4 || instruction_data.len() < 17 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let data = &instruction_data[17..];
            UpdateAuxiliary {
                authority: &accounts[0],
                envelope: &accounts[1],
                pda: &accounts[2],
                program: &accounts[3],
                metadata,
                sequence,
                data,
            }
            .invoke()
        }
        0x02 => {
            // [metadata:8][seq:8][data:rest]
            if accounts.len() < 4 || instruction_data.len() < 17 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let data = &instruction_data[17..];
            UpdateAuxiliaryDelegated {
                envelope: &accounts[1],
                delegation_auth: &accounts[0],
                padding: &accounts[2],
                program: &accounts[3],
                metadata,
                sequence,
                data,
            }
            .invoke()
        }
        0x03 => {
            // [metadata:8][auth_seq:8][prog_seq:8][data:rest]
            if accounts.len() < 4 || instruction_data.len() < 25 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let auth_seq = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let prog_seq = u64::from_le_bytes(instruction_data[17..25].try_into().unwrap());
            let data = &instruction_data[25..];
            UpdateAuxiliaryForce {
                authority: &accounts[0],
                envelope: &accounts[1],
                delegation_auth: &accounts[2],
                program: &accounts[3],
                metadata,
                authority_sequence: auth_seq,
                program_sequence: prog_seq,
                data,
            }
            .invoke()
        }
        0x04 => Ok(()), // Echo
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
