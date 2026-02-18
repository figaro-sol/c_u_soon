mod common;

use c_u_soon::{Envelope, ORACLE_BYTES};
use c_u_soon::Bitmask;
use common::{
    clear_delegation_instruction_data, close_instruction_data, create_delegated_envelope,
    create_existing_envelope, create_existing_envelope_with_bump,
    create_fast_path_instruction_data, create_funded_account, create_instruction_data,
    find_envelope_pda, LOG_LOCK, set_delegated_program_instruction_data, PROGRAM_ID, PROGRAM_PATH,
};
use mollusk_svm::{program::keyed_account_for_system_program, result::Check, Mollusk};
use pinocchio::Address;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_system_interface::program as system_program;

// -- Slow path: Create --

#[test]
fn test_create_happy_path() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let custom_seeds: &[&[u8]] = &[b"test"];
    let (envelope_pda, bump) = find_envelope_pda(&authority, custom_seeds);

    let account_metas = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(envelope_pda, true),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_instruction_data(custom_seeds, bump),
        account_metas,
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pda, create_funded_account(0)),
            keyed_account_for_system_program(),
        ],
        &[Check::success()],
    );

    let envelope: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(envelope.authority, authority);
    assert_eq!(envelope.oracle_state.sequence, 0);
}

#[test]
fn test_create_idempotent() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let custom_seeds: &[&[u8]] = &[b"test"];
    let (envelope_pda, bump) = find_envelope_pda(&authority, custom_seeds);

    let account_metas = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(envelope_pda, false),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_instruction_data(custom_seeds, bump),
        account_metas,
    );

    let existing = create_existing_envelope_with_bump(&authority, 5, bump);

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pda, existing),
            keyed_account_for_system_program(),
        ],
        &[Check::success()],
    );

    let envelope: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(envelope.oracle_state.sequence, 5);
}

#[test]
fn test_create_wrong_pda() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let custom_seeds: &[&[u8]] = &[b"test"];
    let (_, bump) = find_envelope_pda(&authority, custom_seeds);

    let wrong_pda = Address::new_unique();

    let account_metas = vec![
        AccountMeta::new(authority, true),
        AccountMeta::new(wrong_pda, true),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_instruction_data(custom_seeds, bump),
        account_metas,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (wrong_pda, create_funded_account(0)),
            keyed_account_for_system_program(),
        ],
        &[Check::err(
            solana_sdk::program_error::ProgramError::InvalidSeeds,
        )],
    );
}

#[test]
fn test_create_not_signer() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let custom_seeds: &[&[u8]] = &[b"test"];
    let (envelope_pda, bump) = find_envelope_pda(&authority, custom_seeds);

    let account_metas = vec![
        AccountMeta::new_readonly(authority, false), // not signer
        AccountMeta::new(envelope_pda, true),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_instruction_data(custom_seeds, bump),
        account_metas,
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pda, create_funded_account(0)),
            keyed_account_for_system_program(),
        ],
        &[Check::err(
            solana_sdk::program_error::ProgramError::MissingRequiredSignature,
        )],
    );
}

// -- Fast path --

#[test]
fn test_fast_path_update_after_create() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    // Fast path: 2 accounts
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_fast_path_instruction_data(1, &[42]),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
        ],
        &[Check::success()],
    );

    let resulting_envelope: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(resulting_envelope.oracle_state.sequence, 1);
    assert_eq!(resulting_envelope.oracle_state.data[0], 42u8);
}

#[test]
fn test_fast_path_wrong_authority() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let wrong_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    // Fast path with wrong authority → error
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_fast_path_instruction_data(1, &[42]),
        vec![
            AccountMeta::new_readonly(wrong_authority, true),
            AccountMeta::new(envelope_pubkey, false),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (wrong_authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_fast_path_stale_sequence() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 5);

    // Try to update with sequence <= current (5)
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_fast_path_instruction_data(5, &[42]),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_fast_path_full_payload() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    // Fill entire oracle data field: payload = ORACLE_BYTES = 247 bytes.
    // instruction_data_len = 8 + 247 = 255 = u8::MAX; data_size = 255.
    // Copies sequence (8 bytes) + all data bytes (247 bytes) in one shot.
    // The explicit _pad byte at OracleState offset 255 is intentionally left untouched.
    let payload = [0xAB_u8; ORACLE_BYTES];
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &create_fast_path_instruction_data(1, &payload),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
        ],
        &[Check::success()],
    );

    let resulting_envelope: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(resulting_envelope.oracle_state.sequence, 1);
    assert!(resulting_envelope
        .oracle_state
        .data
        .iter()
        .all(|&b| b == 0xAB));
}

#[test]
fn test_fast_path_all_write_sizes() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let _log_guard = LOG_LOCK.write().unwrap();
    let prev_log = log::max_level();
    log::set_max_level(log::LevelFilter::Off);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let mut envelope_account = create_existing_envelope(&authority, 0);

    // Test every valid payload size: 0 bytes (sequence-only) through ORACLE_BYTES (full fill).
    // Each iteration writes [i; i] and verifies the written region + untouched region.
    for i in 0..=ORACLE_BYTES {
        let seq = (i + 1) as u64;
        let payload = vec![i as u8; i];
        let instruction = Instruction::new_with_bytes(
            PROGRAM_ID,
            &create_fast_path_instruction_data(seq, &payload),
            vec![
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(envelope_pubkey, false),
            ],
        );

        let result = mollusk.process_and_validate_instruction(
            &instruction,
            &[
                (authority, create_funded_account(1_000_000_000)),
                (envelope_pubkey, envelope_account),
            ],
            &[Check::success(), Check::compute_units(36)],
        );

        let env: &Envelope = bytemuck::from_bytes(
            &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
        );
        assert_eq!(env.oracle_state.sequence, seq, "sequence wrong at size {i}");
        assert!(
            env.oracle_state.data[..i].iter().all(|&b| b == i as u8),
            "written region wrong at size {i}"
        );
        assert!(
            env.oracle_state.data[i..].iter().all(|&b| b == 0),
            "unwritten region modified at size {i}"
        );

        envelope_account = result.resulting_accounts[1].1.clone();
    }

    log::set_max_level(prev_log);
}

// -- Slow path: Close --

#[test]
fn test_close_happy_path() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let recipient = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 5);
    let envelope_lamports = envelope.lamports;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &close_instruction_data(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new(recipient, false),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (recipient, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    assert_eq!(result.resulting_accounts[1].1.lamports, 0);
    assert_eq!(
        result.resulting_accounts[2].1.lamports,
        envelope_lamports
    );
    assert!(result.resulting_accounts[1].1.data.iter().all(|&b| b == 0));
    assert_eq!(result.resulting_accounts[1].1.owner, pinocchio_system::ID);
}

#[test]
fn test_close_wrong_authority() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let wrong_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let recipient = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &close_instruction_data(),
        vec![
            AccountMeta::new_readonly(wrong_authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new(recipient, false),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (wrong_authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (recipient, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_close_not_program_owned() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let recipient = Address::new_unique();

    let mut envelope = create_existing_envelope(&authority, 0);
    envelope.owner = Address::default();

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &close_instruction_data(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new(recipient, false),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (recipient, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

// -- Slow path: SetDelegatedProgram --

#[test]
fn test_set_delegated_program_happy_path() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let mut program_bitmask = [0xFFu8; c_u_soon::BITMASK_SIZE];
    program_bitmask[0] = 0x00; // byte 0 writable by program
    let user_bitmask = [0xFF; c_u_soon::BITMASK_SIZE]; // nothing writable by user

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(program_bitmask, user_bitmask),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.delegation_authority, delegation_auth);
    assert!(env.has_delegation());
}

#[test]
fn test_set_delegated_program_already_delegated() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let new_delegation_auth = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Bitmask::FULL,
        Bitmask::ZERO,
    );

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(
            [0x00; c_u_soon::BITMASK_SIZE],
            [0xFF; c_u_soon::BITMASK_SIZE],
        ),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(new_delegation_auth, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (new_delegation_auth, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_set_delegated_program_non_canonical_bitmask() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let mut bad_bitmask = [0x00u8; c_u_soon::BITMASK_SIZE];
    bad_bitmask[0] = 0x42; // non-canonical

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(bad_bitmask, [0xFF; c_u_soon::BITMASK_SIZE]),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_set_delegated_program_delegation_not_signer() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(
            [0x00; c_u_soon::BITMASK_SIZE],
            [0xFF; c_u_soon::BITMASK_SIZE],
        ),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, false), // not signer
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

// -- Slow path: ClearDelegation --

#[test]
fn test_clear_delegation_happy_path() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Bitmask::FULL,
        Bitmask::ZERO,
    );

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &clear_delegation_instruction_data(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert!(!env.has_delegation());
    assert_eq!(env.program_bitmask, Bitmask::ZERO);
    assert_eq!(env.user_bitmask, Bitmask::ZERO);
}

#[test]
fn test_clear_delegation_no_delegation() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &clear_delegation_instruction_data(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_clear_delegation_wrong_delegation_auth() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let wrong_delegation_auth = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_auth,
        Bitmask::FULL,
        Bitmask::ZERO,
    );

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &clear_delegation_instruction_data(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(wrong_delegation_auth, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (wrong_delegation_auth, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}
