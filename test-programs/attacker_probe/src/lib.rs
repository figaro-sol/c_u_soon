#![no_std]

use pinocchio::{
    cpi::invoke,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

/// Attack instruction variants for security testing.
/// Format: [discriminant: u8][fields...]
///
/// 0x00: FastPathWithoutAuthoritySigner [seq: u64 LE][payload_len: u8][payload bytes]
///   Accounts: [0]=authority, [1]=envelope(writable), [2]=c_u_soon_program
///   Attack: marks authority as NOT signer → c_u_soon rejects MissingRequiredSignature
///
/// 0x01: FastPathWithWrongAuthority [seq: u64 LE][payload_len: u8][payload bytes]
///   Accounts: [0]=wrong_authority(signer), [1]=envelope(writable), [2]=c_u_soon_program
///   Attack: passes wrong authority (different from envelope.authority) → c_u_soon rejects IncorrectAuthority
///
/// 0x02: WrongDelegationAuthority [seq: u64 LE][aux_data: 256 bytes]
///   Accounts: [0]=envelope(writable), [1]=wrong_delegation(signer), [2]=padding, [3]=c_u_soon_program
///   Attack: wrong delegation_authority → c_u_soon rejects IncorrectAuthority
///
/// 0x03: SlowPathWithoutPdaSigner [seq: u64 LE][aux_data: 256 bytes]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=pda_account(NOT signer), [3]=c_u_soon_program
///   Attack: pda_account not signer when no delegation → c_u_soon rejects MissingRequiredSignature
///
/// 0x04: StaleSequence [seq: u64 LE][payload_len: u8][payload bytes]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=c_u_soon_program
///   Attack: sequence <= envelope.oracle_state.sequence → c_u_soon rejects InvalidInstructionData
///
/// 0x05: Echo

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
            if instruction_data.len() < 10 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let payload_len = instruction_data[9] as usize;
            if instruction_data.len() < 10 + payload_len {
                return Err(ProgramError::InvalidInstructionData);
            }
            let payload = &instruction_data[10..10 + payload_len];
            fast_path_without_authority_signer(accounts, sequence, payload)
        }
        0x01 => {
            if instruction_data.len() < 10 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let payload_len = instruction_data[9] as usize;
            if instruction_data.len() < 10 + payload_len {
                return Err(ProgramError::InvalidInstructionData);
            }
            let payload = &instruction_data[10..10 + payload_len];
            fast_path_with_wrong_authority(accounts, sequence, payload)
        }
        0x02 => {
            if instruction_data.len() < 1 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let aux_data = &instruction_data[9..9 + 256];
            wrong_delegation_authority(accounts, sequence, aux_data)
        }
        0x03 => {
            if instruction_data.len() < 1 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let aux_data = &instruction_data[9..9 + 256];
            slow_path_without_pda_signer(accounts, sequence, aux_data)
        }
        0x04 => {
            if instruction_data.len() < 10 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let payload_len = instruction_data[9] as usize;
            if instruction_data.len() < 10 + payload_len {
                return Err(ProgramError::InvalidInstructionData);
            }
            let payload = &instruction_data[10..10 + payload_len];
            stale_sequence(accounts, sequence, payload)
        }
        0x05 => Ok(()), // Echo
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// ATTACK: CPI to fast path with authority marked as NOT signer.
fn fast_path_without_authority_signer(
    accounts: &[AccountView],
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 8 + 255];
    ix_data[..8].copy_from_slice(&sequence.to_le_bytes());
    let payload_len = payload.len().min(255);
    ix_data[8..8 + payload_len].copy_from_slice(&payload[..payload_len]);
    let ix_data = &ix_data[..8 + payload_len];

    // Attack: mark authority as readonly (NOT signer)
    let cpi_accounts = [
        InstructionAccount::readonly(accounts[0].address()), // authority, NOT signer
        InstructionAccount::writable(accounts[1].address()),  // envelope, writable
    ];
    let instruction = InstructionView {
        program_id: accounts[2].address(),
        accounts: &cpi_accounts,
        data: ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1]])
}

/// ATTACK: Fast path CPI with wrong authority (accounts[0] != envelope.authority).
fn fast_path_with_wrong_authority(
    accounts: &[AccountView],
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 8 + 255];
    ix_data[..8].copy_from_slice(&sequence.to_le_bytes());
    let payload_len = payload.len().min(255);
    ix_data[8..8 + payload_len].copy_from_slice(&payload[..payload_len]);
    let ix_data = &ix_data[..8 + payload_len];

    // Pass accounts[0] (wrong authority) as signer - it IS a signer but doesn't
    // match envelope.authority, so c_u_soon rejects with IncorrectAuthority
    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()), // wrong authority, signer
        InstructionAccount::writable(accounts[1].address()),         // envelope, writable
    ];
    let instruction = InstructionView {
        program_id: accounts[2].address(),
        accounts: &cpi_accounts,
        data: ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1]])
}

/// ATTACK: UpdateAuxiliaryDelegated with wrong delegation authority.
fn wrong_delegation_authority(
    accounts: &[AccountView],
    sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 4 + 8 + 256];
    ix_data[..4].copy_from_slice(&5u32.to_le_bytes()); // UpdateAuxiliaryDelegated
    ix_data[4..12].copy_from_slice(&sequence.to_le_bytes());
    ix_data[12..268].copy_from_slice(&aux_data[..256]);

    let cpi_accounts = [
        InstructionAccount::writable(accounts[0].address()),         // envelope, writable
        InstructionAccount::readonly_signer(accounts[1].address()),  // wrong delegation, signer
        InstructionAccount::readonly(accounts[2].address()),         // padding
    ];
    let instruction = InstructionView {
        program_id: accounts[3].address(),
        accounts: &cpi_accounts,
        data: &ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1], &accounts[2]])
}

/// ATTACK: UpdateAuxiliary (no delegation) with pda_account NOT a signer.
fn slow_path_without_pda_signer(
    accounts: &[AccountView],
    sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 4 + 8 + 256];
    ix_data[..4].copy_from_slice(&4u32.to_le_bytes()); // UpdateAuxiliary
    ix_data[4..12].copy_from_slice(&sequence.to_le_bytes());
    ix_data[12..268].copy_from_slice(&aux_data[..256]);

    // Attack: mark pda_account as NOT signer
    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()),  // authority, signer
        InstructionAccount::writable(accounts[1].address()),          // envelope, writable
        InstructionAccount::readonly(accounts[2].address()),          // pda_account, NOT signer
    ];
    let instruction = InstructionView {
        program_id: accounts[3].address(),
        accounts: &cpi_accounts,
        data: &ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1], &accounts[2]])
}

/// ATTACK: Fast path CPI with stale sequence (sequence <= envelope.oracle_state.sequence).
fn stale_sequence(accounts: &[AccountView], sequence: u64, payload: &[u8]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 8 + 255];
    ix_data[..8].copy_from_slice(&sequence.to_le_bytes());
    let payload_len = payload.len().min(255);
    ix_data[8..8 + payload_len].copy_from_slice(&payload[..payload_len]);
    let ix_data = &ix_data[..8 + payload_len];

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()), // authority, signer
        InstructionAccount::writable(accounts[1].address()),         // envelope, writable
    ];
    let instruction = InstructionView {
        program_id: accounts[2].address(),
        accounts: &cpi_accounts,
        data: ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1]])
}
