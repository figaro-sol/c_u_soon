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
/// 0x00: FastPathWithoutAuthoritySigner [oracle_meta: u64 LE][seq: u64 LE][payload_len: u8][payload bytes]
///   Accounts: [0]=authority, [1]=envelope(writable), [2]=c_u_soon_program
///   Attack: marks authority as NOT signer → c_u_soon rejects MissingRequiredSignature
///
/// 0x01: FastPathWithWrongAuthority [oracle_meta: u64 LE][seq: u64 LE][payload_len: u8][payload bytes]
///   Accounts: [0]=wrong_authority(signer), [1]=envelope(writable), [2]=c_u_soon_program
///   Attack: passes wrong authority (different from envelope.authority) → c_u_soon rejects IncorrectAuthority
///
/// 0x02: WrongDelegationAuthority [metadata: u64 LE][seq: u64 LE][data: rest]
///   Accounts: [0]=wrong_delegation(signer), [1]=envelope(writable), [2]=padding, [3]=c_u_soon_program
///   Attack: wrong delegation_authority → c_u_soon rejects IncorrectAuthority
///
/// 0x03: SlowPathWithoutPdaSigner [metadata: u64 LE][seq: u64 LE][data: rest]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=padding(NOT signer), [3]=c_u_soon_program
///   Attack: UpdateAuxiliary without delegation → c_u_soon rejects InvalidArgument
///
/// 0x04: StaleSequence [oracle_meta: u64 LE][seq: u64 LE][payload_len: u8][payload bytes]
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
            fast_path_without_authority_signer(accounts, oracle_meta, sequence, payload)
        }
        0x01 => {
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
            fast_path_with_wrong_authority(accounts, oracle_meta, sequence, payload)
        }
        0x02 => {
            // [metadata:8][seq:8][data:rest]
            if instruction_data.len() < 17 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let data = &instruction_data[17..];
            wrong_delegation_authority(accounts, metadata, sequence, data)
        }
        0x03 => {
            // [metadata:8][seq:8][data:rest]
            if instruction_data.len() < 17 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let data = &instruction_data[17..];
            slow_path_without_pda_signer(accounts, metadata, sequence, data)
        }
        0x04 => {
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
            stale_sequence(accounts, oracle_meta, sequence, payload)
        }
        0x05 => Ok(()), // Echo
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// ATTACK: CPI to fast path with authority marked as NOT signer.
fn fast_path_without_authority_signer(
    accounts: &[AccountView],
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 8 + 8 + 239];
    ix_data[..8].copy_from_slice(&oracle_meta.to_le_bytes());
    ix_data[8..16].copy_from_slice(&sequence.to_le_bytes());
    let payload_len = payload.len().min(239);
    ix_data[16..16 + payload_len].copy_from_slice(&payload[..payload_len]);
    let ix_data = &ix_data[..16 + payload_len];

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
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 8 + 8 + 239];
    ix_data[..8].copy_from_slice(&oracle_meta.to_le_bytes());
    ix_data[8..16].copy_from_slice(&sequence.to_le_bytes());
    let payload_len = payload.len().min(239);
    ix_data[16..16 + payload_len].copy_from_slice(&payload[..payload_len]);
    let ix_data = &ix_data[..16 + payload_len];

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
/// Wire: [disc:4][metadata:8][sequence:8][data:N]
/// Accounts: [delegation_auth(signer), envelope(writable), padding]
fn wrong_delegation_authority(
    accounts: &[AccountView],
    metadata: u64,
    sequence: u64,
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let data_len = data.len();
    let total = 20 + data_len;
    let mut ix_data = [0u8; 275]; // 4 + 8 + 8 + 255 max
    ix_data[..4].copy_from_slice(&5u32.to_le_bytes()); // UPDATE_AUX_DELEGATED_TAG
    ix_data[4..12].copy_from_slice(&metadata.to_le_bytes());
    ix_data[12..20].copy_from_slice(&sequence.to_le_bytes());
    ix_data[20..20 + data_len].copy_from_slice(data);

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()), // wrong delegation, signer
        InstructionAccount::writable(accounts[1].address()),         // envelope, writable
        InstructionAccount::readonly(accounts[2].address()),         // padding
    ];
    let instruction = InstructionView {
        program_id: accounts[3].address(),
        accounts: &cpi_accounts,
        data: &ix_data[..total],
    };
    invoke(&instruction, &[&accounts[0], &accounts[1], &accounts[2]])
}

/// ATTACK: UpdateAuxiliary without delegation.
/// Wire: [disc:4][metadata:8][sequence:8][data:N]
/// Accounts: [authority(signer), envelope(writable), pda(NOT signer)]
fn slow_path_without_pda_signer(
    accounts: &[AccountView],
    metadata: u64,
    sequence: u64,
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let data_len = data.len();
    let total = 20 + data_len;
    let mut ix_data = [0u8; 275]; // 4 + 8 + 8 + 255 max
    ix_data[..4].copy_from_slice(&4u32.to_le_bytes()); // UPDATE_AUX_TAG
    ix_data[4..12].copy_from_slice(&metadata.to_le_bytes());
    ix_data[12..20].copy_from_slice(&sequence.to_le_bytes());
    ix_data[20..20 + data_len].copy_from_slice(data);

    // Attack: UpdateAuxiliary on envelope without delegation
    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()), // authority, signer
        InstructionAccount::writable(accounts[1].address()),         // envelope, writable
        InstructionAccount::readonly(accounts[2].address()),         // padding
    ];
    let instruction = InstructionView {
        program_id: accounts[3].address(),
        accounts: &cpi_accounts,
        data: &ix_data[..total],
    };
    invoke(&instruction, &[&accounts[0], &accounts[1], &accounts[2]])
}

/// ATTACK: Fast path CPI with stale sequence (sequence <= envelope.oracle_state.sequence).
fn stale_sequence(
    accounts: &[AccountView],
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 8 + 8 + 239];
    ix_data[..8].copy_from_slice(&oracle_meta.to_le_bytes());
    ix_data[8..16].copy_from_slice(&sequence.to_le_bytes());
    let payload_len = payload.len().min(239);
    ix_data[16..16 + payload_len].copy_from_slice(&payload[..payload_len]);
    let ix_data = &ix_data[..16 + payload_len];

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
