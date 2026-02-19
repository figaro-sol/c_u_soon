#![no_std]

use pinocchio::{
    cpi::invoke,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};

/// Legitimate CPI caller for c_u_soon. Used to test valid multi-program CPI paths.
/// Format: [discriminant: u8][fields...]
///
/// 0x00: UpdateViaFastPath   [seq: u64 LE][payload_len: u8][payload bytes]
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
            update_via_fast_path(accounts, oracle_meta, sequence, payload)
        }
        0x01 => {
            if instruction_data.len() < 1 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let aux_data = &instruction_data[9..9 + 256];
            update_via_slow_path(accounts, sequence, aux_data)
        }
        0x02 => {
            if instruction_data.len() < 1 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let sequence = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let aux_data = &instruction_data[9..9 + 256];
            update_via_delegated(accounts, sequence, aux_data)
        }
        0x03 => {
            if instruction_data.len() < 1 + 8 + 8 + 256 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let auth_seq = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let prog_seq = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let aux_data = &instruction_data[17..17 + 256];
            update_via_force(accounts, auth_seq, prog_seq, aux_data)
        }
        0x04 => Ok(()), // Echo
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn update_via_fast_path(
    accounts: &[AccountView],
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    // Fast path instruction data: [oracle_meta: u64 LE][sequence: u64 LE][payload bytes]
    let mut ix_data = [0u8; 8 + 8 + 239];
    ix_data[..8].copy_from_slice(&oracle_meta.to_le_bytes());
    ix_data[8..16].copy_from_slice(&sequence.to_le_bytes());
    let payload_len = payload.len().min(239);
    ix_data[16..16 + payload_len].copy_from_slice(&payload[..payload_len]);
    let ix_data = &ix_data[..8 + 8 + payload_len];

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()), // authority, signer
        InstructionAccount::writable(accounts[1].address()),         // envelope, writable
    ];
    let instruction = InstructionView {
        program_id: accounts[2].address(), // c_u_soon program
        accounts: &cpi_accounts,
        data: ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1]])
}

fn build_slow_path_update_auxiliary(
    buf: &mut [u8; 4 + 8 + 256],
    sequence: u64,
    aux_data: &[u8],
) {
    buf[..4].copy_from_slice(&4u32.to_le_bytes()); // UpdateAuxiliary discriminant
    buf[4..12].copy_from_slice(&sequence.to_le_bytes());
    buf[12..268].copy_from_slice(&aux_data[..256]);
}

fn build_slow_path_update_delegated(
    buf: &mut [u8; 4 + 8 + 256],
    sequence: u64,
    aux_data: &[u8],
) {
    buf[..4].copy_from_slice(&5u32.to_le_bytes()); // UpdateAuxiliaryDelegated discriminant
    buf[4..12].copy_from_slice(&sequence.to_le_bytes());
    buf[12..268].copy_from_slice(&aux_data[..256]);
}

fn build_slow_path_update_force(
    buf: &mut [u8; 4 + 8 + 8 + 256],
    auth_seq: u64,
    prog_seq: u64,
    aux_data: &[u8],
) {
    buf[..4].copy_from_slice(&6u32.to_le_bytes()); // UpdateAuxiliaryForce discriminant
    buf[4..12].copy_from_slice(&auth_seq.to_le_bytes());
    buf[12..20].copy_from_slice(&prog_seq.to_le_bytes());
    buf[20..276].copy_from_slice(&aux_data[..256]);
}

fn update_via_slow_path(
    accounts: &[AccountView],
    sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 4 + 8 + 256];
    build_slow_path_update_auxiliary(&mut ix_data, sequence, aux_data);

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()), // authority, signer
        InstructionAccount::writable(accounts[1].address()),         // envelope, writable
        InstructionAccount::readonly_signer(accounts[2].address()), // pda_account, signer
    ];
    let instruction = InstructionView {
        program_id: accounts[3].address(), // c_u_soon program
        accounts: &cpi_accounts,
        data: &ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1], &accounts[2]])
}

fn update_via_delegated(
    accounts: &[AccountView],
    sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 4 + 8 + 256];
    build_slow_path_update_delegated(&mut ix_data, sequence, aux_data);

    let cpi_accounts = [
        InstructionAccount::writable(accounts[0].address()),         // envelope, writable
        InstructionAccount::readonly_signer(accounts[1].address()),  // delegation_auth, signer
        InstructionAccount::readonly(accounts[2].address()),         // padding
    ];
    let instruction = InstructionView {
        program_id: accounts[3].address(), // c_u_soon program
        accounts: &cpi_accounts,
        data: &ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1], &accounts[2]])
}

fn update_via_force(
    accounts: &[AccountView],
    auth_sequence: u64,
    prog_sequence: u64,
    aux_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let mut ix_data = [0u8; 4 + 8 + 8 + 256];
    build_slow_path_update_force(&mut ix_data, auth_sequence, prog_sequence, aux_data);

    let cpi_accounts = [
        InstructionAccount::readonly_signer(accounts[0].address()), // authority, signer
        InstructionAccount::writable(accounts[1].address()),         // envelope, writable
        InstructionAccount::readonly_signer(accounts[2].address()), // delegation_auth, signer
    ];
    let instruction = InstructionView {
        program_id: accounts[3].address(), // c_u_soon program
        accounts: &cpi_accounts,
        data: &ix_data,
    };
    invoke(&instruction, &[&accounts[0], &accounts[1], &accounts[2]])
}
