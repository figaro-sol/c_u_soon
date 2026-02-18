mod common;

use c_u_soon::{Bitmask, Envelope, AUX_DATA_SIZE, ORACLE_BYTES};
use common::{
    clear_delegation_instruction_data, close_instruction_data, create_delegated_envelope,
    create_existing_envelope, create_existing_envelope_with_bump,
    create_fast_path_instruction_data, create_funded_account, create_instruction_data,
    find_envelope_pda, LOG_LOCK, set_delegated_program_instruction_data,
    update_auxiliary_delegated_instruction_data, update_auxiliary_force_instruction_data,
    update_auxiliary_instruction_data, PROGRAM_ID, PROGRAM_PATH,
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

#[test]
fn test_fast_path_length_modulo_replay() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Start with sequence = 1 so we can observe the truncation drop.
    let mut envelope_account = create_existing_envelope(&authority, 1);

    // Craft a 257-byte instruction so the runtime length header low byte becomes 1.
    const MALFORMED_LEN: usize = 257;
    let payload = vec![0xCD_u8; MALFORMED_LEN - 8];
    let malicious_sequence = 0x0100_u64;
    let instruction_data = create_fast_path_instruction_data(malicious_sequence, &payload);
    assert_eq!(instruction_data.len(), MALFORMED_LEN);

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &instruction_data,
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
        ],
    );

    let first_result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope_account),
        ],
        &[Check::success()],
    );

    let first_envelope: &Envelope = bytemuck::from_bytes(
        &first_result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(first_envelope.oracle_state.sequence, 0);

    envelope_account = first_result.resulting_accounts[1].1.clone();

    let second_result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope_account),
        ],
        &[Check::success()],
    );

    let second_envelope: &Envelope = bytemuck::from_bytes(
        &second_result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(second_envelope.oracle_state.sequence, 0);
}

#[test]
fn test_fast_path_field_isolation_full_payload() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let mut program_bitmask = Bitmask::ZERO;
    program_bitmask.set_bit(0);
    program_bitmask.set_bit(31);
    let mut user_bitmask = Bitmask::ZERO;
    user_bitmask.set_bit(12);
    user_bitmask.set_bit(63);

    let mut envelope_account =
        create_delegated_envelope(&authority, &delegation_auth, program_bitmask, user_bitmask);
    {
        let envelope: &mut Envelope = bytemuck::from_bytes_mut(
            &mut envelope_account.data[..core::mem::size_of::<Envelope>()],
        );
        envelope.bump = 42;
        envelope._padding = [0x11; 7];
        envelope.authority_aux_sequence = 7;
        envelope.program_aux_sequence = 9;
        envelope.auxiliary_data = [0x77; AUX_DATA_SIZE];
    }

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
            (envelope_pubkey, envelope_account),
        ],
        &[Check::success()],
    );

    let envelope: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );

    assert_eq!(envelope.oracle_state.sequence, 1);
    assert!(envelope.oracle_state.data.iter().all(|&b| b == 0xAB));
    assert_eq!(envelope.bump, 42);
    assert_eq!(envelope._padding, [0x11; 7]);
    assert_eq!(envelope.delegation_authority, delegation_auth);
    assert_eq!(envelope.program_bitmask, program_bitmask);
    assert_eq!(envelope.user_bitmask, user_bitmask);
    assert_eq!(envelope.authority_aux_sequence, 7);
    assert_eq!(envelope.program_aux_sequence, 9);
    assert_eq!(envelope.auxiliary_data, [0x77; AUX_DATA_SIZE]);
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
    assert_eq!(result.resulting_accounts[2].1.lamports, envelope_lamports);
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

#[test]
fn test_close_delegated_rejected() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let recipient = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

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

#[test]
fn test_close_after_clear_delegation() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let recipient = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    // Step 1: ClearDelegation
    let clear_ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &clear_delegation_instruction_data(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &clear_ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let cleared_envelope = result.resulting_accounts[1].1.clone();
    let envelope_lamports = cleared_envelope.lamports;

    // Step 2: Close should now succeed
    let close_ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &close_instruction_data(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new(recipient, false),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &close_ix,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, cleared_envelope),
            (recipient, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    assert_eq!(result.resulting_accounts[1].1.lamports, 0);
    assert_eq!(result.resulting_accounts[2].1.lamports, envelope_lamports);
    assert!(result.resulting_accounts[1].1.data.iter().all(|&b| b == 0));
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

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

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

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

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

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

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

// -- Slow path: UpdateAuxiliary --

#[test]
fn test_update_auxiliary_full_write_no_delegation() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xAA;
    aux_data[127] = 0xBB;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, aux_data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.authority_aux_sequence, 1);
    assert_eq!(env.auxiliary_data[0], 0xAA);
    assert_eq!(env.auxiliary_data[127], 0xBB);
}

#[test]
fn test_update_auxiliary_masked_write_with_delegation() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let padding = Address::new_unique();

    // user_bitmask: only byte 0 writable
    let mut user_bitmask = Bitmask::ZERO;
    user_bitmask.set_bit(0);

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::ZERO, user_bitmask);

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xAA; // allowed

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, aux_data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[0], 0xAA);
    assert_eq!(env.authority_aux_sequence, 1);
}

#[test]
fn test_update_auxiliary_masked_write_blocked() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let padding = Address::new_unique();

    // user_bitmask: only byte 0 writable, byte 1 blocked
    let mut user_bitmask = Bitmask::ZERO;
    user_bitmask.set_bit(0);

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::ZERO, user_bitmask);

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xAA;
    aux_data[1] = 0xBB; // blocked!

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, aux_data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_update_auxiliary_stale_sequence() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let aux_data = [0u8; AUX_DATA_SIZE];

    // First update: seq=1
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, aux_data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let updated_envelope = result.resulting_accounts[1].1.clone();

    // Second update: seq=1 again (stale)
    let instruction2 = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, aux_data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result2 = mollusk.process_instruction(
        &instruction2,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, updated_envelope),
            (padding, create_funded_account(0)),
        ],
    );
    assert!(result2.program_result.is_err());
}

// -- Slow path: UpdateAuxiliaryDelegated --

#[test]
fn test_update_auxiliary_delegated_happy_path() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let padding = Address::new_unique();

    // program_bitmask: byte 0 writable
    let mut program_bitmask = Bitmask::ZERO;
    program_bitmask.set_bit(0);

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, program_bitmask, Bitmask::ZERO);

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xCC;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_instruction_data(1, aux_data),
        vec![
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[0].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[0], 0xCC);
    assert_eq!(env.program_aux_sequence, 1);
}

#[test]
fn test_update_auxiliary_delegated_no_delegation() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let envelope_pubkey = Address::new_unique();
    let authority = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let padding = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let aux_data = [0u8; AUX_DATA_SIZE];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_instruction_data(1, aux_data),
        vec![
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
            (padding, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_update_auxiliary_delegated_wrong_delegation_auth() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let wrong_delegation_auth = Address::new_unique();
    let padding = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    let aux_data = [0u8; AUX_DATA_SIZE];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_instruction_data(1, aux_data),
        vec![
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(wrong_delegation_auth, true),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (envelope_pubkey, envelope),
            (wrong_delegation_auth, create_funded_account(0)),
            (padding, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

#[test]
fn test_update_auxiliary_delegated_stale_sequence() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let padding = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    let aux_data = [0u8; AUX_DATA_SIZE];

    // First update: seq=1
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_instruction_data(1, aux_data),
        vec![
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let updated_envelope = result.resulting_accounts[0].1.clone();

    // Second: seq=1 again (stale)
    let instruction2 = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_instruction_data(1, aux_data),
        vec![
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result2 = mollusk.process_instruction(
        &instruction2,
        &[
            (envelope_pubkey, updated_envelope),
            (delegation_auth, create_funded_account(0)),
            (padding, create_funded_account(0)),
        ],
    );
    assert!(result2.program_result.is_err());
}

#[test]
fn test_update_auxiliary_delegated_bitmask_violation() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let padding = Address::new_unique();

    // program_bitmask: only byte 0 writable
    let mut program_bitmask = Bitmask::ZERO;
    program_bitmask.set_bit(0);

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, program_bitmask, Bitmask::ZERO);

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xCC;
    aux_data[1] = 0xDD; // blocked by program_bitmask

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_instruction_data(1, aux_data),
        vec![
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
            AccountMeta::new_readonly(padding, true),
        ],
    );

    let result = mollusk.process_instruction(
        &instruction,
        &[
            (envelope_pubkey, envelope),
            (delegation_auth, create_funded_account(0)),
            (padding, create_funded_account(0)),
        ],
    );
    assert!(result.program_result.is_err());
}

// -- Slow path: UpdateAuxiliaryForce --

#[test]
fn test_update_auxiliary_force_happy_path() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xDD;
    aux_data[127] = 0xEE;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(1, 1, aux_data),
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
    assert_eq!(env.auxiliary_data[0], 0xDD);
    assert_eq!(env.auxiliary_data[127], 0xEE);
    assert_eq!(env.authority_aux_sequence, 1);
    assert_eq!(env.program_aux_sequence, 1);
}

#[test]
fn test_update_auxiliary_force_authority_not_signer() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    let aux_data = [0u8; AUX_DATA_SIZE];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(1, 1, aux_data),
        vec![
            AccountMeta::new_readonly(authority, false), // not signer
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
fn test_update_auxiliary_force_no_delegation() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let aux_data = [0u8; AUX_DATA_SIZE];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(1, 1, aux_data),
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
fn test_update_auxiliary_force_stale_authority_sequence() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    let aux_data = [0u8; AUX_DATA_SIZE];

    // First: succeed with (1, 1)
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(1, 1, aux_data),
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

    let updated_envelope = result.resulting_accounts[1].1.clone();

    // Second: stale authority_sequence (1 again), fresh program_sequence (2)
    let instruction2 = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(1, 2, aux_data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
        ],
    );

    let result2 = mollusk.process_instruction(
        &instruction2,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, updated_envelope),
            (delegation_auth, create_funded_account(0)),
        ],
    );
    assert!(result2.program_result.is_err());
}

#[test]
fn test_update_auxiliary_force_stale_program_sequence() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    let aux_data = [0u8; AUX_DATA_SIZE];

    // First: succeed with (1, 1)
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(1, 1, aux_data),
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

    let updated_envelope = result.resulting_accounts[1].1.clone();

    // Second: fresh authority_sequence (2), stale program_sequence (1)
    let instruction2 = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(2, 1, aux_data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_auth, true),
        ],
    );

    let result2 = mollusk.process_instruction(
        &instruction2,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, updated_envelope),
            (delegation_auth, create_funded_account(0)),
        ],
    );
    assert!(result2.program_result.is_err());
}

#[test]
fn test_update_auxiliary_force_wrong_delegation_auth() {
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let delegation_auth = Address::new_unique();
    let wrong_delegation_auth = Address::new_unique();

    let envelope =
        create_delegated_envelope(&authority, &delegation_auth, Bitmask::FULL, Bitmask::ZERO);

    let aux_data = [0u8; AUX_DATA_SIZE];

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(1, 1, aux_data),
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
