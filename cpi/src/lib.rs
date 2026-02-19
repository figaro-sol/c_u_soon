#![no_std]

use c_u_soon::{AUX_DATA_SIZE, ORACLE_BYTES};
use pinocchio::{
    cpi::invoke,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

const UPDATE_AUX_DISC: u32 = 4;
const UPDATE_AUX_DELEGATED_DISC: u32 = 5;
const UPDATE_AUX_FORCE_DISC: u32 = 6;

const SLOW_AUX_SIZE: usize = 4 + 8 + AUX_DATA_SIZE; // 268
const SLOW_AUX_FORCE_SIZE: usize = 4 + 8 + 8 + AUX_DATA_SIZE; // 276
const FAST_PATH_MAX: usize = 8 + 8 + ORACLE_BYTES; // 255

/// CPI: fast path oracle update.
/// Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=c_u_soon program.
pub fn invoke_fast_path(
    accounts: &[AccountView],
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    let payload_len = payload.len().min(ORACLE_BYTES);
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
    let mut buf = [0u8; SLOW_AUX_SIZE];
    buf[..4].copy_from_slice(&UPDATE_AUX_DISC.to_le_bytes());
    buf[4..12].copy_from_slice(&sequence.to_le_bytes());
    buf[12..12 + AUX_DATA_SIZE].copy_from_slice(data);

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
    let mut buf = [0u8; SLOW_AUX_SIZE];
    buf[..4].copy_from_slice(&UPDATE_AUX_DELEGATED_DISC.to_le_bytes());
    buf[4..12].copy_from_slice(&sequence.to_le_bytes());
    buf[12..12 + AUX_DATA_SIZE].copy_from_slice(data);

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
    let mut buf = [0u8; SLOW_AUX_FORCE_SIZE];
    buf[..4].copy_from_slice(&UPDATE_AUX_FORCE_DISC.to_le_bytes());
    buf[4..12].copy_from_slice(&authority_sequence.to_le_bytes());
    buf[12..20].copy_from_slice(&program_sequence.to_le_bytes());
    buf[20..20 + AUX_DATA_SIZE].copy_from_slice(data);

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
