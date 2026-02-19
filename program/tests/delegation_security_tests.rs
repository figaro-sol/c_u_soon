mod common;

use bytemuck::Zeroable;
use c_u_soon::{Envelope, Mask, AUX_DATA_SIZE};
use c_u_soon_client::{
    clear_delegation_instruction_data, set_delegated_program_instruction_data,
    update_auxiliary_delegated_instruction_data, update_auxiliary_force_instruction_data,
    update_auxiliary_instruction_data,
};
use common::{
    create_delegated_envelope, create_existing_envelope, create_funded_account, LOG_LOCK,
    PROGRAM_ID, PROGRAM_PATH,
};
use mollusk_svm::result::Check;
use mollusk_svm::Mollusk;
use pinocchio::{error::ProgramError, Address};
use solana_sdk::instruction::{AccountMeta, Instruction};

// -- Delegation Security Tests --

#[test]
fn test_set_delegated_program_happy_path() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let mut program_bitmask = Mask::ALL_BLOCKED;
    program_bitmask.allow(0);
    let mut user_bitmask = Mask::ALL_BLOCKED;
    user_bitmask.allow(0);

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(program_bitmask, user_bitmask).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.delegation_authority, delegation_authority);
    assert_eq!(env.program_bitmask, program_bitmask);
    assert_eq!(env.user_bitmask, user_bitmask);
}

#[test]
fn test_set_delegated_program_rejects_if_delegation_exists() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let existing_delegation = Address::new_unique();
    let new_delegation = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let existing_bitmask = Mask::ALL_WRITABLE;
    let envelope = create_delegated_envelope(
        &authority,
        &existing_delegation,
        existing_bitmask,
        existing_bitmask,
    );

    let mut new_program_bitmask = Mask::ALL_BLOCKED;
    new_program_bitmask.allow(0);
    let mut new_user_bitmask = Mask::ALL_BLOCKED;
    new_user_bitmask.allow(0);

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(new_program_bitmask, new_user_bitmask).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(new_delegation, true),
        ],
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (new_delegation, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_clear_delegation_happy_path() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_authority,
        Mask::ALL_WRITABLE,
        Mask::ALL_WRITABLE,
    );

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &clear_delegation_instruction_data().unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.delegation_authority, Address::zeroed());
    assert_eq!(env.program_bitmask, Mask::ALL_BLOCKED);
    assert_eq!(env.user_bitmask, Mask::ALL_BLOCKED);
    // Verify oracle_state.data and auxiliary_data are zeroed
    assert_eq!(env.oracle_state.data, [0u8; c_u_soon::ORACLE_BYTES]);
    assert_eq!(env.auxiliary_data, [0u8; AUX_DATA_SIZE]);
}

#[test]
fn test_update_auxiliary_with_delegation_applies_bitmask() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Only allow byte 0 to be written
    let mut user_bitmask = Mask::ALL_BLOCKED;
    user_bitmask.allow(0);

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_authority,
        Mask::ALL_BLOCKED,
        user_bitmask,
    );

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xAA;
    aux_data[1] = 0xBB;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, aux_data).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(pda, true),
        ],
    );

    // This should fail because byte 1 is blocked by the bitmask
    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_update_auxiliary_delegated_happy_path() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let authority = Address::new_unique();
    let padding = Address::new_unique();

    // Allow all program writes, block all user writes
    let program_bitmask = Mask::ALL_WRITABLE;
    let user_bitmask = Mask::ALL_BLOCKED;

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_authority,
        program_bitmask,
        user_bitmask,
    );

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xCC;
    aux_data[50] = 0xDD;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_delegated_instruction_data(1, aux_data).unwrap(),
        vec![
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
            AccountMeta::new_readonly(padding, false),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(0)),
            (padding, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[0].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[0], 0xCC);
    assert_eq!(env.auxiliary_data[50], 0xDD);
    assert_eq!(env.program_aux_sequence, 1);
}

#[test]
fn test_update_auxiliary_force_happy_path() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_authority,
        Mask::ALL_WRITABLE,
        Mask::ALL_WRITABLE,
    );

    let mut aux_data = [0u8; AUX_DATA_SIZE];
    aux_data[0] = 0xEE;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(5, 10, aux_data).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(0)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.auxiliary_data[0], 0xEE);
    assert_eq!(env.authority_aux_sequence, 5);
    assert_eq!(env.program_aux_sequence, 10);
}

#[test]
fn test_update_auxiliary_force_fails_without_delegation() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let aux_data = [0u8; AUX_DATA_SIZE];
    let delegation_authority = Address::new_unique();

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(5, 10, aux_data).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
        ],
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn test_sequence_monotonically_increases() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();
    let pda = Address::new_unique();

    // Create envelope with authority_aux_sequence = 20
    let mut envelope_account = create_existing_envelope(&authority, 0);
    let envelope_data_mut = &mut envelope_account.data;
    let envelope: &mut Envelope = bytemuck::from_bytes_mut(envelope_data_mut);
    envelope.authority_aux_sequence = 20;

    let aux_data = [0xAAu8; AUX_DATA_SIZE];

    // Try to write with sequence <= current sequence (10 <= 20)
    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(10, aux_data).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(pda, true),
        ],
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope_account),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}
