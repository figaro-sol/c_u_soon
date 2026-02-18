#![allow(dead_code)]

use bytemuck::{bytes_of, Zeroable};
use c_u_soon::{
    Bitmask, Envelope, OracleState, SlowPathInstruction, AUX_DATA_SIZE, ENVELOPE_SEED, ORACLE_BYTES,
};
use pinocchio::Address;
use solana_sdk::account::Account;
use std::sync::RwLock;

pub static LOG_LOCK: RwLock<()> = RwLock::new(());

pub const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/deploy/c_u_soon_program"
);

pub const PROGRAM_ID: Address = Address::new_from_array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
]);

pub fn find_envelope_pda(authority: &Address, custom_seeds: &[&[u8]]) -> (Address, u8) {
    let mut seeds: Vec<&[u8]> = vec![ENVELOPE_SEED, authority.as_ref()];
    seeds.extend(custom_seeds);
    Address::find_program_address(&seeds, &PROGRAM_ID)
}

/// Build create instruction data using wincode serialization
pub fn create_instruction_data(custom_seeds: &[&[u8]], bump: u8) -> Vec<u8> {
    let seeds_vecs: Vec<Vec<u8>> = custom_seeds.iter().map(|s| s.to_vec()).collect();
    let ix = SlowPathInstruction::Create {
        custom_seeds: seeds_vecs,
        bump,
    };
    wincode::serialize(&ix).unwrap()
}

pub fn create_funded_account(lamports: u64) -> Account {
    Account {
        lamports,
        data: vec![],
        owner: Address::default(),
        executable: false,
        rent_epoch: 0,
    }
}

pub fn create_existing_envelope(authority: &Address, seq: u64) -> Account {
    create_existing_envelope_with_bump(authority, seq, 0)
}

pub fn create_existing_envelope_with_bump(authority: &Address, seq: u64, bump: u8) -> Account {
    let envelope = Envelope {
        authority: *authority,
        oracle_state: OracleState {
            sequence: seq,
            data: [0u8; ORACLE_BYTES],
            _pad: [0u8; 1],
        },
        bump,
        _padding: [0u8; 7],
        delegation_authority: Address::zeroed(),
        program_bitmask: Bitmask::ZERO,
        user_bitmask: Bitmask::ZERO,
        authority_aux_sequence: 0,
        program_aux_sequence: 0,
        auxiliary_data: [0u8; AUX_DATA_SIZE],
    };
    Account {
        lamports: 1_000_000_000,
        data: bytes_of(&envelope).to_vec(),
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

pub fn close_instruction_data() -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::Close).unwrap()
}

pub fn set_delegated_program_instruction_data(
    program_bitmask: [u8; c_u_soon::BITMASK_SIZE],
    user_bitmask: [u8; c_u_soon::BITMASK_SIZE],
) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::SetDelegatedProgram {
        program_bitmask,
        user_bitmask,
    })
    .unwrap()
}

pub fn clear_delegation_instruction_data() -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::ClearDelegation).unwrap()
}

pub fn create_delegated_envelope(
    authority: &Address,
    delegation_authority: &Address,
    program_bitmask: Bitmask,
    user_bitmask: Bitmask,
) -> Account {
    let envelope = Envelope {
        authority: *authority,
        oracle_state: OracleState {
            sequence: 0,
            data: [0u8; ORACLE_BYTES],
            _pad: [0u8; 1],
        },
        bump: 0,
        _padding: [0u8; 7],
        delegation_authority: *delegation_authority,
        program_bitmask,
        user_bitmask,
        authority_aux_sequence: 0,
        program_aux_sequence: 0,
        auxiliary_data: [0u8; AUX_DATA_SIZE],
    };
    Account {
        lamports: 1_000_000_000,
        data: bytes_of(&envelope).to_vec(),
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

pub fn update_auxiliary_instruction_data(sequence: u64, data: [u8; AUX_DATA_SIZE]) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliary { sequence, data }).unwrap()
}

pub fn update_auxiliary_force_instruction_data(
    authority_sequence: u64,
    program_sequence: u64,
    data: [u8; AUX_DATA_SIZE],
) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliaryForce {
        authority_sequence,
        program_sequence,
        data,
    })
    .unwrap()
}

pub fn update_auxiliary_delegated_instruction_data(
    sequence: u64,
    data: [u8; AUX_DATA_SIZE],
) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliaryDelegated { sequence, data }).unwrap()
}

/// Build fast path instruction data: sequence (u64 LE) followed by raw payload bytes
pub fn create_fast_path_instruction_data(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + payload.len());
    data.extend_from_slice(&sequence.to_le_bytes());
    data.extend_from_slice(payload);
    data
}
