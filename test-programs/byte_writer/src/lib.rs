#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use c_u_soon_cpi::{
    FastPathUpdate, UpdateAuxiliary, UpdateAuxiliaryDelegated, UpdateAuxiliaryDelegatedMultiRange,
    UpdateAuxiliaryDelegatedRange, UpdateAuxiliaryForce, UpdateAuxiliaryMultiRange,
    UpdateAuxiliaryRange,
};
use c_u_soon_instruction::WriteSpec;
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
///
/// 0x05: UpdateViaRangeSlowPath [metadata: u64 LE][seq: u64 LE][offset: u8][data: rest]
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=pda(signer), [3]=c_u_soon_program
///
/// 0x06: UpdateViaDelegatedRange [metadata: u64 LE][seq: u64 LE][offset: u8][data: rest]
///   Accounts: [0]=delegation_auth(signer), [1]=envelope(writable), [2]=padding, [3]=c_u_soon_program
///
/// 0x07: UpdateViaMultiRangeSlowPath [metadata: u64 LE][seq: u64 LE][count: u8][(offset: u8)(len: u8)(data: len bytes)]...
///   Accounts: [0]=authority(signer), [1]=envelope(writable), [2]=pda(signer), [3]=c_u_soon_program
///
/// 0x08: UpdateViaDelegatedMultiRange [metadata: u64 LE][seq: u64 LE][count: u8][(offset: u8)(len: u8)(data: len bytes)]...
///   Accounts: [0]=delegation_auth(signer), [1]=envelope(writable), [2]=padding, [3]=c_u_soon_program

pinocchio::program_entrypoint!(process_instruction);
pinocchio::default_allocator!();
pinocchio::nostd_panic_handler!();

fn parse_ranges(data: &[u8]) -> Result<Vec<WriteSpec>, ProgramError> {
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let count = data[0] as usize;
    let mut pos = 1;
    let mut specs = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let offset = data[pos];
        let len = data[pos + 1] as usize;
        pos += 2;
        if pos + len > data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        specs.push(WriteSpec {
            offset,
            data: data[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    Ok(specs)
}

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
        0x05 => {
            // [metadata:8][seq:8][offset:1][data:rest]
            if accounts.len() < 4 || instruction_data.len() < 18 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let offset = instruction_data[17];
            let data = &instruction_data[18..];
            UpdateAuxiliaryRange {
                authority: &accounts[0],
                envelope: &accounts[1],
                pda: &accounts[2],
                program: &accounts[3],
                metadata,
                sequence,
                offset,
                data,
            }
            .invoke()
        }
        0x06 => {
            // [metadata:8][seq:8][offset:1][data:rest]
            if accounts.len() < 4 || instruction_data.len() < 18 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let offset = instruction_data[17];
            let data = &instruction_data[18..];
            UpdateAuxiliaryDelegatedRange {
                envelope: &accounts[1],
                delegation_auth: &accounts[0],
                padding: &accounts[2],
                program: &accounts[3],
                metadata,
                sequence,
                offset,
                data,
            }
            .invoke()
        }
        0x07 => {
            // [metadata:8][seq:8][ranges_data:rest]
            if accounts.len() < 4 || instruction_data.len() < 17 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let ranges = parse_ranges(&instruction_data[17..])?;
            UpdateAuxiliaryMultiRange {
                authority: &accounts[0],
                envelope: &accounts[1],
                pda: &accounts[2],
                program: &accounts[3],
                metadata,
                sequence,
                ranges: &ranges,
            }
            .invoke()
        }
        0x08 => {
            // [metadata:8][seq:8][ranges_data:rest]
            if accounts.len() < 4 || instruction_data.len() < 17 {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(instruction_data[1..9].try_into().unwrap());
            let sequence = u64::from_le_bytes(instruction_data[9..17].try_into().unwrap());
            let ranges = parse_ranges(&instruction_data[17..])?;
            UpdateAuxiliaryDelegatedMultiRange {
                envelope: &accounts[1],
                delegation_auth: &accounts[0],
                padding: &accounts[2],
                program: &accounts[3],
                metadata,
                sequence,
                ranges: &ranges,
            }
            .invoke()
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
