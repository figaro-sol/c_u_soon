#![no_std]

use c_u_soon::{AUX_DATA_SIZE, ORACLE_BYTES};
use c_u_soon_instruction::{
    SlowPathInstruction, UPDATE_AUX_FORCE_SERIALIZED_SIZE, UPDATE_AUX_SERIALIZED_SIZE,
};
use pinocchio::{
    cpi::invoke,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

const FAST_PATH_MAX: usize = 8 + 8 + ORACLE_BYTES; // 255

/// CPI: fast path oracle update.
pub fn invoke_fast_path(
    authority: &AccountView,
    envelope: &AccountView,
    program: &AccountView,
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if payload.len() > ORACLE_BYTES {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payload_len = payload.len();
    let mut buf = [0u8; FAST_PATH_MAX];
    buf[..8].copy_from_slice(&oracle_meta.to_le_bytes());
    buf[8..16].copy_from_slice(&sequence.to_le_bytes());
    buf[16..16 + payload_len].copy_from_slice(&payload[..payload_len]);

    let cpi_accounts = [
        InstructionAccount::readonly_signer(authority.address()),
        InstructionAccount::writable(envelope.address()),
    ];
    let ix = InstructionView {
        program_id: program.address(),
        accounts: &cpi_accounts,
        data: &buf[..16 + payload_len],
    };
    invoke(&ix, &[authority, envelope])
}

/// CPI: UpdateAuxiliary (authority writes aux data).
pub fn invoke_update_auxiliary(
    authority: &AccountView,
    envelope: &AccountView,
    pda: &AccountView,
    program: &AccountView,
    sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    let ix_enum = SlowPathInstruction::UpdateAuxiliary {
        sequence,
        data: *data,
    };
    let mut buf = [0u8; UPDATE_AUX_SERIALIZED_SIZE];
    wincode::serialize_into(&mut &mut buf[..], &ix_enum)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    let cpi_accounts = [
        InstructionAccount::readonly_signer(authority.address()),
        InstructionAccount::writable(envelope.address()),
        InstructionAccount::readonly_signer(pda.address()),
    ];
    let ix = InstructionView {
        program_id: program.address(),
        accounts: &cpi_accounts,
        data: &buf,
    };
    invoke(&ix, &[authority, envelope, pda])
}

/// CPI: UpdateAuxiliaryDelegated (delegation program writes aux data).
pub fn invoke_update_auxiliary_delegated(
    envelope: &AccountView,
    delegation_auth: &AccountView,
    padding: &AccountView,
    program: &AccountView,
    sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    let ix_enum = SlowPathInstruction::UpdateAuxiliaryDelegated {
        sequence,
        data: *data,
    };
    let mut buf = [0u8; UPDATE_AUX_SERIALIZED_SIZE];
    wincode::serialize_into(&mut &mut buf[..], &ix_enum)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    let cpi_accounts = [
        InstructionAccount::readonly_signer(delegation_auth.address()),
        InstructionAccount::writable(envelope.address()),
        InstructionAccount::readonly(padding.address()),
    ];
    let ix = InstructionView {
        program_id: program.address(),
        accounts: &cpi_accounts,
        data: &buf,
    };
    invoke(&ix, &[delegation_auth, envelope, padding])
}

/// CPI: UpdateAuxiliaryForce (authority overrides both sequences).
pub fn invoke_update_auxiliary_force(
    authority: &AccountView,
    envelope: &AccountView,
    delegation_auth: &AccountView,
    program: &AccountView,
    authority_sequence: u64,
    program_sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    let ix_enum = SlowPathInstruction::UpdateAuxiliaryForce {
        authority_sequence,
        program_sequence,
        data: *data,
    };
    let mut buf = [0u8; UPDATE_AUX_FORCE_SERIALIZED_SIZE];
    wincode::serialize_into(&mut &mut buf[..], &ix_enum)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    let cpi_accounts = [
        InstructionAccount::readonly_signer(authority.address()),
        InstructionAccount::writable(envelope.address()),
        InstructionAccount::readonly_signer(delegation_auth.address()),
    ];
    let ix = InstructionView {
        program_id: program.address(),
        accounts: &cpi_accounts,
        data: &buf,
    };
    invoke(&ix, &[authority, envelope, delegation_auth])
}
