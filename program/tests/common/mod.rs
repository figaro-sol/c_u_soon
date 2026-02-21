#![allow(dead_code)]

use bytemuck::{bytes_of, Zeroable};
use c_u_soon::{
    Envelope, Mask, OracleState, StructMetadata, AUX_DATA_SIZE, ENVELOPE_SEED, ORACLE_BYTES,
};
use mollusk_svm::Mollusk;
use pinocchio::Address;
use solana_sdk::account::Account;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

static LOG_LOCK: RwLock<()> = RwLock::new(());

// Guard that holds a Mollusk and the log lock for its lifetime.
// Generic over the lock kind so read-lock and write-lock tests share one type.
pub struct MolluskGuard<G> {
    pub mollusk: Mollusk,
    _log: G,
}

impl<G> std::ops::Deref for MolluskGuard<G> {
    type Target = Mollusk;
    fn deref(&self) -> &Mollusk {
        &self.mollusk
    }
}

impl<G> std::ops::DerefMut for MolluskGuard<G> {
    fn deref_mut(&mut self) -> &mut Mollusk {
        &mut self.mollusk
    }
}

// Write guard wrapper that restores the log level on drop.
pub struct LogWriteGuard {
    _inner: RwLockWriteGuard<'static, ()>,
    prev_level: log::LevelFilter,
}

impl Drop for LogWriteGuard {
    fn drop(&mut self) {
        log::set_max_level(self.prev_level);
    }
}

/// Normal test: acquires read lock, constructs Mollusk, holds lock for test lifetime.
pub fn new_mollusk(
    program_id: &Address,
    program_name: &str,
) -> MolluskGuard<RwLockReadGuard<'static, ()>> {
    let _log = LOG_LOCK.read().unwrap_or_else(|e| e.into_inner());
    let mollusk = Mollusk::new(program_id, program_name);
    MolluskGuard { mollusk, _log }
}

/// Log-suppressing test: acquires write lock, sets log level to `level`, constructs Mollusk.
/// Previous log level is restored automatically when the guard drops.
pub fn new_mollusk_silent(
    program_id: &Address,
    program_name: &str,
    level: log::LevelFilter,
) -> MolluskGuard<LogWriteGuard> {
    let _inner = LOG_LOCK.write().unwrap_or_else(|e| e.into_inner());
    // Mollusk::new calls setup_with_default() which resets the log level, so
    // capture prev_level and set our desired level only after construction.
    let mollusk = Mollusk::new(program_id, program_name);
    let prev_level = log::max_level();
    log::set_max_level(level);
    MolluskGuard {
        mollusk,
        _log: LogWriteGuard { _inner, prev_level },
    }
}

pub const PROGRAM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/deploy/c_u_soon_program"
);

pub const TEST_TYPE_SIZE: usize = 200;
pub const TEST_META: StructMetadata = StructMetadata::new(TEST_TYPE_SIZE as u8, 0);
pub const TEST_META_U64: u64 = TEST_META.as_u64();

pub const PROGRAM_ID: Address = Address::new_from_array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
]);

pub fn find_envelope_pda(authority: &Address, custom_seeds: &[&[u8]]) -> (Address, u8) {
    let mut seeds: Vec<&[u8]> = vec![ENVELOPE_SEED, authority.as_ref()];
    seeds.extend(custom_seeds);
    Address::find_program_address(&seeds, &PROGRAM_ID)
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
            oracle_metadata: StructMetadata::ZERO,
            sequence: seq,
            data: [0u8; ORACLE_BYTES],
            _pad: [0u8; 1],
        },
        bump,
        _padding: [0u8; 7],
        delegation_authority: Address::zeroed(),
        program_bitmask: Mask::ALL_BLOCKED,
        user_bitmask: Mask::ALL_BLOCKED,
        authority_aux_sequence: 0,
        program_aux_sequence: 0,
        auxiliary_metadata: TEST_META,
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

pub fn create_delegated_envelope(
    authority: &Address,
    delegation_authority: &Address,
    program_bitmask: Mask,
    user_bitmask: Mask,
) -> Account {
    let envelope = Envelope {
        authority: *authority,
        oracle_state: OracleState {
            oracle_metadata: StructMetadata::ZERO,
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
        auxiliary_metadata: TEST_META,
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
