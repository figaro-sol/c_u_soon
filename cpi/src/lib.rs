#![no_std]

extern crate alloc;

use c_u_soon::{AUX_DATA_SIZE, ORACLE_BYTES};
use c_u_soon_instruction::SlowPathInstruction;
use pinocchio::{
    cpi::invoke,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

const FAST_PATH_MAX: usize = 8 + 8 + ORACLE_BYTES; // 255

/// CPI: fast path oracle update.
/// Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=c_u_soon program.
pub fn invoke_fast_path(
    accounts: &[AccountView],
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if payload.len() > ORACLE_BYTES {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payload_len = payload.len();
    let mut buf = [0u8; FAST_PATH_MAX];
    buf[..8].copy_from_slice(&oracle_meta.to_le_bytes());
    buf[8..16].copy_from_slice(&sequence.to_le_bytes());
    buf[16..16 + payload_len].copy_from_slice(&payload[..payload_len]);

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()),
        InstructionAccount::writable(accounts[1].address()),
    ];
    let ix = InstructionView {
        program_id: accounts[2].address(),
        accounts: &cpi_accounts,
        data: &buf[..16 + payload_len],
    };
    invoke(&ix, &[&accounts[0], &accounts[1]])
}

/// CPI: UpdateAuxiliary (authority writes aux data).
/// Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=pda(signer), [3]=c_u_soon program.
pub fn invoke_update_auxiliary(
    accounts: &[AccountView],
    sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let ix_enum = SlowPathInstruction::UpdateAuxiliary {
        sequence,
        data: *data,
    };
    let buf = wincode::serialize(&ix_enum).map_err(|_| ProgramError::InvalidInstructionData)?;

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()),
        InstructionAccount::writable(accounts[1].address()),
        InstructionAccount::readonly_signer(accounts[2].address()),
    ];
    let ix = InstructionView {
        program_id: accounts[3].address(),
        accounts: &cpi_accounts,
        data: &buf,
    };
    invoke(&ix, &[&accounts[0], &accounts[1], &accounts[2]])
}

/// CPI: UpdateAuxiliaryDelegated (delegation program writes aux data).
/// Accounts: [0]=envelope(writable), [1]=delegation_auth(signer), [2]=padding, [3]=c_u_soon program.
pub fn invoke_update_auxiliary_delegated(
    accounts: &[AccountView],
    sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let ix_enum = SlowPathInstruction::UpdateAuxiliaryDelegated {
        sequence,
        data: *data,
    };
    let buf = wincode::serialize(&ix_enum).map_err(|_| ProgramError::InvalidInstructionData)?;

    let cpi_accounts = [
        InstructionAccount::writable(accounts[0].address()),
        InstructionAccount::readonly_signer(accounts[1].address()),
        InstructionAccount::readonly(accounts[2].address()),
    ];
    let ix = InstructionView {
        program_id: accounts[3].address(),
        accounts: &cpi_accounts,
        data: &buf,
    };
    invoke(&ix, &[&accounts[0], &accounts[1], &accounts[2]])
}

/// CPI: UpdateAuxiliaryForce (authority overrides both sequences).
/// Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=delegation_auth(signer), [3]=c_u_soon program.
pub fn invoke_update_auxiliary_force(
    accounts: &[AccountView],
    authority_sequence: u64,
    program_sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let ix_enum = SlowPathInstruction::UpdateAuxiliaryForce {
        authority_sequence,
        program_sequence,
        data: *data,
    };
    let buf = wincode::serialize(&ix_enum).map_err(|_| ProgramError::InvalidInstructionData)?;

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()),
        InstructionAccount::writable(accounts[1].address()),
        InstructionAccount::readonly_signer(accounts[2].address()),
    ];
    let ix = InstructionView {
        program_id: accounts[3].address(),
        accounts: &cpi_accounts,
        data: &buf,
    };
    invoke(&ix, &[&accounts[0], &accounts[1], &accounts[2]])
}
