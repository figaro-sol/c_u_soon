mod common;

use c_u_soon::{Envelope, Mask, AUX_DATA_SIZE};
use c_u_soon_client::{
    update_auxiliary_delegated_range_instruction_data, update_auxiliary_range_instruction_data,
};
use common::{
    create_delegated_envelope, create_funded_account, new_mollusk, new_mollusk_silent, PROGRAM_ID,
    PROGRAM_PATH, TEST_META_U64, TEST_TYPE_SIZE,
};
use mollusk_svm::result::Check;
use pinocchio::{error::ProgramError, Address};
use solana_sdk::instruction::{AccountMeta, Instruction};

// ============================================================================
// Helpers
// ============================================================================

fn range_instruction(
    authority: &Address,
    envelope_pubkey: &Address,
    pda: &Address,
    metadata: u64,
    sequence: u64,
    offset: u8,
    data: &[u8],
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_range_instruction_data(metadata, sequence, offset, data),
        vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*envelope_pubkey, false),
            AccountMeta::new_readonly(*pda, true),
        ],
    )
}

fn delegated_range_instruction(
    delegation_auth: &Address,
    envelope_pubkey: &Address,
    padding: &Address,
    metadata: u64,
    sequence: u64,
    offset: u8,
    data: &[u8],
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_range_instruction_data(metadata, sequence, offset, data),
        vec![
            AccountMeta::new_readonly(*delegation_auth, true),
            AccountMeta::new(*envelope_pubkey, false),
            AccountMeta::new_readonly(*padding, false),
        ],
    )
}

// ============================================================================
// Authority Range Update — Happy Path
// ============================================================================

#[test]
fn test_range_write_at_offset_zero() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let write_data = [0xAA; 8];
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &write_data,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(&env.auxiliary_data[..8], &[0xAA; 8]);
    assert_eq!(env.authority_aux_sequence, 1);
    // Bytes outside range untouched
    assert!(env.auxiliary_data[8..TEST_TYPE_SIZE]
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn test_range_write_at_middle_offset() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let write_data = [0xBB; 8];
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        50,
        &write_data,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert!(env.auxiliary_data[..50].iter().all(|&b| b == 0));
    assert_eq!(&env.auxiliary_data[50..58], &[0xBB; 8]);
    assert!(env.auxiliary_data[58..TEST_TYPE_SIZE]
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn test_range_write_single_byte_at_last_offset() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let write_data = [0xFF];
    let offset = (TEST_TYPE_SIZE - 1) as u8;
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        offset,
        &write_data,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[TEST_TYPE_SIZE - 1], 0xFF);
    assert!(env.auxiliary_data[..TEST_TYPE_SIZE - 1]
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn test_range_write_full_type_size() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let write_data: Vec<u8> = (0..TEST_TYPE_SIZE as u8).collect();
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &write_data,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(&env.auxiliary_data[..TEST_TYPE_SIZE], &write_data[..]);
    assert_eq!(env.authority_aux_sequence, 1);
}

#[test]
fn test_range_sequence_updated() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        42,
        0,
        &[0x01],
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.authority_aux_sequence, 42);
}

// ============================================================================
// Authority Range Update — Boundary
// ============================================================================

#[test]
fn test_range_tight_fit_at_end() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // offset + len = type_size exactly
    let offset = (TEST_TYPE_SIZE - 1) as u8;
    let write_data = [0xDD];
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        offset,
        &write_data,
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );
}

// ============================================================================
// Authority Range Update — Rejection
// ============================================================================

#[test]
fn test_range_reject_overflow() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // offset + len > type_size
    let offset = (TEST_TYPE_SIZE - 1) as u8;
    let write_data = [0xAA; 2]; // extends 1 byte past type_size
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        offset,
        &write_data,
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_range_reject_empty_data() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // Empty data: just the header with no payload
    let ix = range_instruction(&authority, &envelope_pubkey, &pda, TEST_META_U64, 1, 0, &[]);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_range_reject_bad_metadata() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let bad_meta = 0xDEAD_BEEF_u64;
    let ix = range_instruction(&authority, &envelope_pubkey, &pda, bad_meta, 1, 0, &[0x01]);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_range_reject_wrong_authority() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let wrong_authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let ix = range_instruction(
        &wrong_authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (wrong_authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::IncorrectAuthority)],
    );
}

#[test]
fn test_range_reject_missing_signer() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // Authority NOT marked as signer
    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_range_instruction_data(TEST_META_U64, 1, 0, &[0x01]),
        vec![
            AccountMeta::new_readonly(authority, false), // not a signer
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(pda, true),
        ],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::MissingRequiredSignature)],
    );
}

#[test]
fn test_range_reject_wrong_owner() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Envelope owned by wrong program
    let mut envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );
    envelope.owner = Address::new_unique();

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::IncorrectProgramId)],
    );
}

#[test]
fn test_range_reject_stale_sequence() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // sequence 0 <= current 0, rejected
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        0,
        0,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_range_reject_no_delegation() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // No delegation (create_existing_envelope has zeroed delegation_authority)
    let envelope = common::create_existing_envelope(&authority, 0);

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

// ============================================================================
// Authority Range Update — Mask Interaction
// ============================================================================

#[test]
fn test_range_mask_fully_writable() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        10,
        &[0xAA; 20],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );
}

#[test]
fn test_range_mask_fully_blocked() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_BLOCKED,
    );

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &[0xAA],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_range_mask_start_writable_end_blocked() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Bytes 0..4 writable, bytes 4+ blocked
    let mut user_bitmask = Mask::ALL_BLOCKED;
    for i in 0..4 {
        user_bitmask.allow(i);
    }

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );

    // Range [2..6) crosses from writable to blocked
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        2,
        &[0xAA; 4],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_range_mask_start_blocked_end_writable() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Bytes 4..8 writable, rest blocked
    let mut user_bitmask = Mask::ALL_BLOCKED;
    for i in 4..8 {
        user_bitmask.allow(i);
    }

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );

    // Range [2..6) starts in blocked, ends in writable
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        2,
        &[0xAA; 4],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_range_mask_single_blocked_byte_in_middle() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // All writable except byte 5
    let mut user_bitmask = Mask::ALL_WRITABLE;
    user_bitmask.block(5);

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );

    // Range [3..8) includes blocked byte 5
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        3,
        &[0xAA; 5],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

// ============================================================================
// Authority Range Update — Isolation
// ============================================================================

#[test]
fn test_range_two_sequential_updates() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // First update: bytes [0..4)
    let ix1 = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &[0xAA; 4],
    );
    let result1 = mollusk.process_and_validate_instruction(
        &ix1,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    // Second update: bytes [10..14), on the result of first
    let ix2 = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        2,
        10,
        &[0xBB; 4],
    );
    let result2 = mollusk.process_and_validate_instruction(
        &ix2,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, result1.resulting_accounts[1].1.clone()),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result2.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(&env.auxiliary_data[..4], &[0xAA; 4]);
    assert!(env.auxiliary_data[4..10].iter().all(|&b| b == 0));
    assert_eq!(&env.auxiliary_data[10..14], &[0xBB; 4]);
    assert!(env.auxiliary_data[14..TEST_TYPE_SIZE]
        .iter()
        .all(|&b| b == 0));
    assert_eq!(env.authority_aux_sequence, 2);
}

#[test]
fn test_range_update_does_not_touch_other_fields() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        0,
        &[0xFF; 8],
    );
    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.authority, authority);
    assert_eq!(env.delegation_authority, delegation_auth);
    assert_eq!(env.oracle_state.sequence, 0);
    assert_eq!(env.program_aux_sequence, 0);
    // Only the range was written
    assert_eq!(&env.auxiliary_data[..8], &[0xFF; 8]);
    assert!(env.auxiliary_data[8..TEST_TYPE_SIZE]
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn test_range_update_does_not_touch_bytes_outside_range() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Pre-fill aux_data with known pattern
    let mut envelope_account = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );
    {
        let env: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_account.data);
        for i in 0..AUX_DATA_SIZE {
            env.auxiliary_data[i] = (i & 0xFF) as u8;
        }
    }

    // Write 4 bytes at offset 10
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        10,
        &[0xAA; 4],
    );
    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope_account),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    // Before the range
    for i in 0..10 {
        assert_eq!(env.auxiliary_data[i], (i & 0xFF) as u8);
    }
    // The range
    assert_eq!(&env.auxiliary_data[10..14], &[0xAA; 4]);
    // After the range
    for i in 14..AUX_DATA_SIZE {
        assert_eq!(env.auxiliary_data[i], (i & 0xFF) as u8);
    }
}

// ============================================================================
// Delegated Range Update — Happy Path
// ============================================================================

#[test]
fn test_delegated_range_write() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_WRITABLE,
        Mask::ALL_BLOCKED,
    );

    let write_data = [0xCC; 16];
    let ix = delegated_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        20,
        &write_data,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (delegation_auth, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(&env.auxiliary_data[20..36], &[0xCC; 16]);
    assert_eq!(env.program_aux_sequence, 1);
    assert_eq!(env.authority_aux_sequence, 0); // untouched
}

// ============================================================================
// Delegated Range Update — Rejection
// ============================================================================

#[test]
fn test_delegated_range_reject_no_delegation() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = common::create_existing_envelope(&authority, 0);

    let ix = delegated_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        0,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (delegation_auth, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_delegated_range_reject_wrong_authority() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let real_delegation = Address::new_unique();
    let wrong_delegation = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &real_delegation,
        Mask::ALL_WRITABLE,
        Mask::ALL_BLOCKED,
    );

    let ix = delegated_range_instruction(
        &wrong_delegation,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        0,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (wrong_delegation, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::IncorrectAuthority)],
    );
}

#[test]
fn test_delegated_range_reject_overflow() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_WRITABLE,
        Mask::ALL_BLOCKED,
    );

    let offset = (TEST_TYPE_SIZE - 1) as u8;
    let ix = delegated_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        offset,
        &[0xAA; 2],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (delegation_auth, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_delegated_range_reject_stale_sequence() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_WRITABLE,
        Mask::ALL_BLOCKED,
    );

    let ix = delegated_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        0,
        0,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (delegation_auth, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_delegated_range_mask_blocked() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    // program_bitmask blocks byte 5
    let mut program_bitmask = Mask::ALL_WRITABLE;
    program_bitmask.block(5);

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        program_bitmask,
        Mask::ALL_BLOCKED,
    );

    // Range [3..8) includes blocked byte 5
    let ix = delegated_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        3,
        &[0xAA; 5],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (delegation_auth, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

// ============================================================================
// Edge Cases — Boundary Offsets
// ============================================================================

use c_u_soon::{OracleState, StructMetadata, ORACLE_BYTES};

fn create_delegated_envelope_with_meta(
    authority: &Address,
    delegation_authority: &Address,
    program_bitmask: Mask,
    user_bitmask: Mask,
    meta: StructMetadata,
) -> solana_sdk::account::Account {
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
        auxiliary_metadata: meta,
        auxiliary_data: [0u8; AUX_DATA_SIZE],
    };
    solana_sdk::account::Account {
        lamports: 1_000_000_000,
        data: bytemuck::bytes_of(&envelope).to_vec(),
        owner: PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

#[test]
fn test_range_reject_offset_past_type_size() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // offset=201 > type_size=200, with 1 byte data
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        TEST_TYPE_SIZE as u8 + 1,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_range_reject_offset_exactly_at_type_size() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );

    // offset=200 == type_size=200, with 1 byte data → overflow
    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        TEST_TYPE_SIZE as u8,
        &[0x01],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn test_range_max_type_size_last_byte() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // type_size=255 (maximum), offset=254, len=1 → success (last byte)
    let meta_255 = StructMetadata::new(255, 0);
    let envelope = create_delegated_envelope_with_meta(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
        meta_255,
    );

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        meta_255.as_u64(),
        1,
        254,
        &[0xEE],
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[254], 0xEE);
    assert_eq!(env.authority_aux_sequence, 1);
}

#[test]
fn test_range_max_type_size_overflow_by_one() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // type_size=255, offset=254, len=2 → overflow by 1
    let meta_255 = StructMetadata::new(255, 0);
    let envelope = create_delegated_envelope_with_meta(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
        meta_255,
    );

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        meta_255.as_u64(),
        1,
        254,
        &[0xAA; 2],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

// ============================================================================
// Unified Mask Semantics — Blocked-Unchanged Succeeds
// ============================================================================

#[test]
fn test_range_blocked_byte_unchanged_succeeds() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Byte 5 blocked, rest writable
    let mut user_bitmask = Mask::ALL_WRITABLE;
    user_bitmask.block(5);

    let mut envelope_account = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );
    // Pre-set byte 5 to 0x42
    {
        let env: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_account.data);
        env.auxiliary_data[5] = 0x42;
    }

    // Write range [3..8): src[2]=0x42 matches dest[5], so blocked byte unchanged
    let mut write_data = [0xAA; 5];
    write_data[2] = 0x42; // maps to byte 5

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        3,
        &write_data,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope_account),
            (pda, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[3], 0xAA);
    assert_eq!(env.auxiliary_data[4], 0xAA);
    assert_eq!(env.auxiliary_data[5], 0x42); // unchanged
    assert_eq!(env.auxiliary_data[6], 0xAA);
    assert_eq!(env.auxiliary_data[7], 0xAA);
}

#[test]
fn test_range_blocked_byte_changed_fails() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Byte 5 blocked, rest writable
    let mut user_bitmask = Mask::ALL_WRITABLE;
    user_bitmask.block(5);

    let mut envelope_account = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );
    {
        let env: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_account.data);
        env.auxiliary_data[5] = 0x42;
    }

    // Write range [3..8): src[2]=0x99 differs from dest[5]=0x42
    let mut write_data = [0xAA; 5];
    write_data[2] = 0x99; // maps to byte 5, CHANGED

    let ix = range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        3,
        &write_data,
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope_account),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_delegated_range_blocked_byte_unchanged_succeeds() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let mut program_bitmask = Mask::ALL_WRITABLE;
    program_bitmask.block(5);

    let mut envelope_account = create_delegated_envelope(
        &authority,
        &delegation_auth,
        program_bitmask,
        Mask::ALL_BLOCKED,
    );
    {
        let env: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_account.data);
        env.auxiliary_data[5] = 0x42;
    }

    let mut write_data = [0xCC; 5];
    write_data[2] = 0x42; // maps to byte 5, unchanged

    let ix = delegated_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        3,
        &write_data,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (delegation_auth, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope_account),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[3], 0xCC);
    assert_eq!(env.auxiliary_data[5], 0x42);
    assert_eq!(env.auxiliary_data[7], 0xCC);
}
