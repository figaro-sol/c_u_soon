mod common;

use c_u_soon::{Envelope, Mask};
use c_u_soon_client::{
    update_auxiliary_delegated_multi_range_instruction_data,
    update_auxiliary_multi_range_instruction_data,
};
use c_u_soon_instruction::WriteSpec;
use common::{
    create_delegated_envelope, create_existing_envelope, create_funded_account, new_mollusk,
    new_mollusk_silent, PROGRAM_ID, PROGRAM_PATH, TEST_META_U64, TEST_TYPE_SIZE,
};
use mollusk_svm::result::Check;
use pinocchio::{error::ProgramError, Address};
use solana_sdk::instruction::{AccountMeta, Instruction};

// ============================================================================
// Helpers
// ============================================================================

fn make_specs(ranges: &[(u8, &[u8])]) -> Vec<WriteSpec> {
    ranges
        .iter()
        .map(|(offset, data)| WriteSpec {
            offset: *offset,
            data: data.to_vec(),
        })
        .collect()
}

fn multi_range_instruction(
    authority: &Address,
    envelope_pubkey: &Address,
    pda: &Address,
    metadata: u64,
    sequence: u64,
    ranges: &[WriteSpec],
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_multi_range_instruction_data(metadata, sequence, ranges),
        vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*envelope_pubkey, false),
            AccountMeta::new_readonly(*pda, true),
        ],
    )
}

fn delegated_multi_range_instruction(
    delegation_auth: &Address,
    envelope_pubkey: &Address,
    padding: &Address,
    metadata: u64,
    sequence: u64,
    ranges: &[WriteSpec],
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_multi_range_instruction_data(metadata, sequence, ranges),
        vec![
            AccountMeta::new_readonly(*delegation_auth, true),
            AccountMeta::new(*envelope_pubkey, false),
            AccountMeta::new_readonly(*padding, false),
        ],
    )
}

// ============================================================================
// Authority Multi-Range — Happy Path
// ============================================================================

#[test]
fn test_multi_range_single_range() {
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

    let ranges = make_specs(&[(0, &[0xAA; 8])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
    assert!(env.auxiliary_data[8..TEST_TYPE_SIZE]
        .iter()
        .all(|&b| b == 0));
    assert_eq!(env.authority_aux_sequence, 1);
}

#[test]
fn test_multi_range_two_non_overlapping() {
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

    let ranges = make_specs(&[(0, &[0xAA; 4]), (50, &[0xBB; 8])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
    assert_eq!(&env.auxiliary_data[..4], &[0xAA; 4]);
    assert!(env.auxiliary_data[4..50].iter().all(|&b| b == 0));
    assert_eq!(&env.auxiliary_data[50..58], &[0xBB; 8]);
    assert!(env.auxiliary_data[58..TEST_TYPE_SIZE]
        .iter()
        .all(|&b| b == 0));
    assert_eq!(env.authority_aux_sequence, 1);
}

#[test]
fn test_multi_range_three_ranges() {
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

    let ranges = make_specs(&[(0, &[0x11; 2]), (10, &[0x22; 3]), (100, &[0x33; 1])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
    assert_eq!(&env.auxiliary_data[..2], &[0x11; 2]);
    assert_eq!(&env.auxiliary_data[10..13], &[0x22; 3]);
    assert_eq!(env.auxiliary_data[100], 0x33);
}

// ============================================================================
// Authority Multi-Range — Rejection
// ============================================================================

#[test]
fn test_multi_range_reject_empty_ranges() {
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

    let ranges: Vec<WriteSpec> = vec![];
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_multi_range_reject_empty_data_in_spec() {
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

    let ranges = vec![WriteSpec {
        offset: 5,
        data: vec![],
    }];
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_multi_range_reject_overflow_type_size() {
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

    // offset=199 (TEST_TYPE_SIZE-1), len=2 overflows type_size
    let ranges = make_specs(&[((TEST_TYPE_SIZE - 1) as u8, &[0xAA; 2])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_multi_range_reject_bad_metadata() {
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

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = multi_range_instruction(&authority, &envelope_pubkey, &pda, 0xDEAD_BEEF, 1, &ranges);

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
fn test_multi_range_reject_wrong_authority() {
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

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = multi_range_instruction(
        &wrong_authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_multi_range_reject_missing_signer() {
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

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_multi_range_instruction_data(TEST_META_U64, 1, &ranges),
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
fn test_multi_range_reject_stale_sequence() {
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

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        0,
        &ranges,
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
fn test_multi_range_reject_no_delegation() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
// Authority Multi-Range — Overlap
// ============================================================================

#[test]
fn test_multi_range_overlap_last_write_wins() {
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

    // Two ranges at same offset: second overwrites first
    let ranges = make_specs(&[(0, &[0xAA; 4]), (0, &[0xBB; 4])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
    assert_eq!(&env.auxiliary_data[..4], &[0xBB; 4]);
}

#[test]
fn test_multi_range_partial_overlap() {
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

    // Range 1: [0..4) = 0xAA, Range 2: [2..6) = 0xBB
    let ranges = make_specs(&[(0, &[0xAA; 4]), (2, &[0xBB; 4])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
    // [0..2) = AA from first range, [2..6) = BB from second range
    assert_eq!(&env.auxiliary_data[..2], &[0xAA; 2]);
    assert_eq!(&env.auxiliary_data[2..6], &[0xBB; 4]);
}

// ============================================================================
// Authority Multi-Range — Mask
// ============================================================================

#[test]
fn test_multi_range_all_ranges_writable_succeeds() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Bytes 0..8 and 50..58 writable
    let mut user_bitmask = Mask::ALL_BLOCKED;
    for i in 0..8 {
        user_bitmask.allow(i);
    }
    for i in 50..58 {
        user_bitmask.allow(i);
    }

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );

    let ranges = make_specs(&[(0, &[0xAA; 4]), (50, &[0xBB; 8])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_multi_range_one_blocked_range_rejects_all() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Only bytes 0..8 writable
    let mut user_bitmask = Mask::ALL_BLOCKED;
    for i in 0..8 {
        user_bitmask.allow(i);
    }

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );

    // First range OK, second range in blocked region
    let ranges = make_specs(&[
        (0, &[0xAA; 4]),
        (50, &[0xBB; 4]), // blocked
    ]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
// Delegated Multi-Range — Happy Path
// ============================================================================

#[test]
fn test_delegated_multi_range_two_ranges() {
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

    let ranges = make_specs(&[(10, &[0xCC; 8]), (30, &[0xDD; 4])]);
    let ix = delegated_multi_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        &ranges,
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
    assert_eq!(&env.auxiliary_data[10..18], &[0xCC; 8]);
    assert_eq!(&env.auxiliary_data[30..34], &[0xDD; 4]);
    assert_eq!(env.program_aux_sequence, 1);
    assert_eq!(env.authority_aux_sequence, 0); // untouched
}

// ============================================================================
// Delegated Multi-Range — Rejection
// ============================================================================

#[test]
fn test_delegated_multi_range_reject_no_delegation() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = delegated_multi_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_delegated_multi_range_reject_wrong_authority() {
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

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = delegated_multi_range_instruction(
        &wrong_delegation,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_delegated_multi_range_reject_stale_sequence() {
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

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = delegated_multi_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        0,
        &ranges,
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
fn test_delegated_multi_range_mask_blocked() {
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
    let ranges = make_specs(&[(3, &[0xAA; 5])]);
    let ix = delegated_multi_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        &ranges,
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
// Authority Multi-Range — Wrong Owner
// ============================================================================

#[test]
fn test_multi_range_reject_wrong_owner() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let mut envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        Mask::ALL_WRITABLE,
    );
    envelope.owner = Address::new_unique();

    let ranges = make_specs(&[(0, &[0xAA])]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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

// ============================================================================
// Trailing Data Rejection
// ============================================================================

#[test]
fn test_multi_range_reject_trailing_data() {
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

    // Build valid wincode data, then append garbage
    let ranges = make_specs(&[(0, &[0xAA])]);
    let mut ix_data = update_auxiliary_multi_range_instruction_data(TEST_META_U64, 1, &ranges);
    ix_data.push(0xFF); // trailing garbage

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &ix_data,
        vec![
            AccountMeta::new_readonly(authority, true),
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
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

// ============================================================================
// Unified Mask Semantics — Blocked-Unchanged Succeeds
// ============================================================================

#[test]
fn test_multi_range_blocked_byte_unchanged_succeeds() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Byte 5 blocked
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

    // Range covers [3..8), src[2]=0x42 matches dest[5]
    let mut data = [0xAA; 5];
    data[2] = 0x42;
    let ranges = make_specs(&[(3, &data)]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
    assert_eq!(env.auxiliary_data[5], 0x42);
    assert_eq!(env.auxiliary_data[7], 0xAA);
}

#[test]
fn test_multi_range_blocked_byte_changed_fails() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

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

    // Range covers [3..8), src[2]=0x99 differs from dest[5]=0x42
    let mut data = [0xAA; 5];
    data[2] = 0x99;
    let ranges = make_specs(&[(3, &data)]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_multi_range_atomicity_second_range_fails_no_partial_write() {
    let mollusk = new_mollusk_silent(&PROGRAM_ID, PROGRAM_PATH, log::LevelFilter::Off);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let mut user_bitmask = Mask::ALL_WRITABLE;
    user_bitmask.block(50);

    let mut envelope_account = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );
    {
        let env: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_account.data);
        env.auxiliary_data[50] = 0x42;
    }

    // First range valid, second changes blocked byte → entire tx fails
    let ranges = make_specs(&[
        (0, &[0xAA; 4]),
        (48, &[0xBB; 4]), // byte 50 changed: 0xBB != 0x42
    ]);
    let ix = multi_range_instruction(
        &authority,
        &envelope_pubkey,
        &pda,
        TEST_META_U64,
        1,
        &ranges,
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
fn test_delegated_multi_range_blocked_byte_unchanged_succeeds() {
    let mollusk = new_mollusk(&PROGRAM_ID, PROGRAM_PATH);
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let mut program_bitmask = Mask::ALL_WRITABLE;
    program_bitmask.block(15);

    let mut envelope_account = create_delegated_envelope(
        &authority,
        &delegation_auth,
        program_bitmask,
        Mask::ALL_BLOCKED,
    );
    {
        let env: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_account.data);
        env.auxiliary_data[15] = 0x77;
    }

    let mut data = [0xDD; 8];
    data[5] = 0x77; // maps to byte 15, unchanged
    let ranges = make_specs(&[(10, &data)]);
    let ix = delegated_multi_range_instruction(
        &delegation_auth,
        &envelope_pubkey,
        &padding,
        TEST_META_U64,
        1,
        &ranges,
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
    assert_eq!(env.auxiliary_data[10], 0xDD);
    assert_eq!(env.auxiliary_data[15], 0x77);
    assert_eq!(env.auxiliary_data[17], 0xDD);
}
