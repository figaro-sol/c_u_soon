use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg,
    program_error::ProgramError, pubkey::Pubkey,
};

/// Instruction variants for byte_writer test program
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum ByteWriterInstruction {
    /// Call c_u_soon fast path directly (requires authority signer)
    UpdateViaFastPath { sequence: u64, payload: Vec<u8> },

    /// Call c_u_soon slow path with full auxiliary data
    UpdateViaSlowPath { sequence: u64, aux_data: Vec<u8> },

    /// Call c_u_soon slow path with delegation
    UpdateViaDelegated { sequence: u64, aux_data: Vec<u8> },

    /// Call c_u_soon slow path with both authority and delegated authority signing
    UpdateViaForce {
        auth_sequence: u64,
        prog_sequence: u64,
        aux_data: Vec<u8>,
    },

    /// Echo instruction - just return success (for testing instruction parsing)
    Echo,
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction: ByteWriterInstruction = borsh::from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        ByteWriterInstruction::UpdateViaFastPath { sequence, payload } => {
            update_via_fast_path(program_id, accounts, sequence, &payload)
        }
        ByteWriterInstruction::UpdateViaSlowPath { sequence, aux_data } => {
            update_via_slow_path(program_id, accounts, sequence, &aux_data)
        }
        ByteWriterInstruction::UpdateViaDelegated { sequence, aux_data } => {
            update_via_delegated(program_id, accounts, sequence, &aux_data)
        }
        ByteWriterInstruction::UpdateViaForce {
            auth_sequence,
            prog_sequence,
            aux_data,
        } => update_via_force(program_id, accounts, auth_sequence, prog_sequence, &aux_data),
        ByteWriterInstruction::Echo => Ok(()),
    }
}

fn update_via_fast_path(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // Fast path doesn't actually invoke c_u_soon in this test version
    // In real usage, this would construct and send a CPI to c_u_soon's fast path
    // For now, we just verify the structure is valid
    msg!("UpdateViaFastPath: sequence={}, payload_len={}", sequence, payload.len());
    Ok(())
}

fn update_via_slow_path(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    msg!("UpdateViaSlowPath: sequence={}, aux_data_len={}", sequence, aux_data.len());
    Ok(())
}

fn update_via_delegated(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    msg!("UpdateViaDelegated: sequence={}, aux_data_len={}", sequence, aux_data.len());
    Ok(())
}

fn update_via_force(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    auth_sequence: u64,
    prog_sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    msg!("UpdateViaForce: auth_seq={}, prog_seq={}, aux_data_len={}", auth_sequence, prog_sequence, aux_data.len());
    Ok(())
}
