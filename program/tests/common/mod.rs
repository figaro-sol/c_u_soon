#![allow(dead_code)]

use bytemuck::bytes_of;
use c_u_soon::{Envelope, OracleState, ENVELOPE_SEED, ORACLE_BYTES};
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

/// Build create instruction data: [discriminator=0] ++ [num_seeds, [len, data...]..., bump]
pub fn create_instruction_data(custom_seeds: &[&[u8]], bump: u8) -> Vec<u8> {
    let mut data = vec![0u8]; // discriminator
    data.push(custom_seeds.len() as u8);
    for seed in custom_seeds {
        data.push(seed.len() as u8);
        data.extend_from_slice(seed);
    }
    data.push(bump);
    data
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
    let envelope = Envelope {
        authority: *authority,
        oracle_state: OracleState {
            sequence: seq,
            data: [0u8; ORACLE_BYTES],
            _pad: [0u8; 1],
        },
    };
    Account {
        lamports: 1_000_000_000,
        data: bytes_of(&envelope).to_vec(),
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

/// Build fast path instruction data: sequence (u64 LE) followed by raw payload bytes
pub fn create_fast_path_instruction_data(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + payload.len());
    data.extend_from_slice(&sequence.to_le_bytes());
    data.extend_from_slice(payload);
    data
}
