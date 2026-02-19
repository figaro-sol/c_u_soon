#![no_std]

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Legitimate CPI caller for c_u_soon. Used to test valid multi-program CPI paths.
/// Format: [discriminant: u8][fields...]
///
/// 0x00: UpdateViaFastPath   [oracle_meta: u64 LE][seq: u64 LE][payload_len: u8][payload bytes]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=c_u_soon_program
///
/// 0x01: UpdateViaSlowPath   [seq: u64 LE][aux_data: 256 bytes]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=pda_account(signer), [3]=c_u_soon_program
///
/// 0x02: UpdateViaDelegated  [seq: u64 LE][aux_data: 256 bytes]
///   Accounts: [0]=envelope(writable), [1]=delegation_auth(signer), [2]=padding, [3]=c_u_soon_program
///
/// 0x03: UpdateViaForce      [auth_seq: u64 LE][prog_seq: u64 LE][aux_data: 256 bytes]
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
            if instruction_data.len() < 18 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let oracle_meta = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let payload_len = instruction_data[17] as usize;
            if instruction_data.len() < 18 + payload_len {
                return Err(ProgramError::InvalidInstructionData);
            }
            let payload = &instruction_data[18..18 + payload_len];
            c_u_soon_cpi::invoke_fast_path(accounts, oracle_meta, sequence, payload)
        }
        0x01 => {
            if instruction_data.len() < 1 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let aux_data: &[u8; 256] = instruction_data[9..9 + 256].try_into().unwrap();
            c_u_soon_cpi::invoke_update_auxiliary(accounts, sequence, aux_data)
        }
        0x02 => {
            if instruction_data.len() < 1 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let aux_data: &[u8; 256] = instruction_data[9..9 + 256].try_into().unwrap();
            c_u_soon_cpi::invoke_update_auxiliary_delegated(accounts, sequence, aux_data)
        }
        0x03 => {
            if instruction_data.len() < 1 + 8 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let auth_seq = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let prog_seq = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let aux_data: &[u8; 256] = instruction_data[17..17 + 256].try_into().unwrap();
            c_u_soon_cpi::invoke_update_auxiliary_force(accounts, auth_seq, prog_seq, aux_data)
        }
        0x04 => Ok(()), // Echo
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
