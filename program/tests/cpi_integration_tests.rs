mod common;

use c_u_soon::{Bitmask, Envelope, AUX_DATA_SIZE};
use common::{
    create_delegated_envelope, create_existing_envelope, create_funded_account,
    set_delegated_program_instruction_data, update_auxiliary_force_instruction_data,
    update_auxiliary_instruction_data, LOG_LOCK, PROGRAM_ID, PROGRAM_PATH,
};
use mollusk_svm::result::Check;
use mollusk_svm::Mollusk;
use pinocchio::{Address, error::ProgramError};
use solana_sdk::instruction::{AccountMeta, Instruction};

// -- Security Integration Tests --
// These tests verify core security properties of c_u_soon

/// Test that delegated writes with bitmask restrictions are enforced
/// When a delegation is set with restricted user_bitmask, writes outside that mask must be rejected
#[test]
fn test_delegated_bitmask_enforcement() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    // Create a delegated envelope where only byte 0 can be written
    let mut user_bitmask = [0xFFu8; 128];
    user_bitmask[0] = 0x00; // Allow write to byte 0 only
    let program_bitmask = Bitmask::from([0xFFu8; 128]); // Block all program writes

    let envelope = create_delegated_envelope(&authority, &delegation_authority, program_bitmask, Bitmask::from(user_bitmask));

    let mut data = [0u8; AUX_DATA_SIZE];
    data[0] = 0xAA; // Allowed (byte 0)
    data[1] = 0xBB; // NOT allowed (byte 1)

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, data),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(pda, true),
        ],
    );

    // This should fail because data[1] violates the bitmask
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

/// Test that authorization is required for delegation modifications
/// Only authority can set delegation
#[test]
fn test_delegation_requires_authority() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let imposter = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let mut program_bitmask = [0xFFu8; 128];
    program_bitmask[0] = 0x00;
    let mut user_bitmask = [0xFFu8; 128];
    user_bitmask[0] = 0x00;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(program_bitmask, user_bitmask),
        vec![
            AccountMeta::new_readonly(imposter, true), // Wrong authority
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
        ],
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (imposter, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::IncorrectAuthority)],
    );
}

/// Test that UpdateAuxiliaryForce correctly bumps both sequences
#[test]
fn test_force_update_increments_sequences() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let program_bitmask = [0x00u8; 128]; // Allow all
    let user_bitmask = [0x00u8; 128]; // Allow all

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_authority,
        Bitmask::from(program_bitmask),
        Bitmask::from(user_bitmask),
    );

    let mut data = [0u8; AUX_DATA_SIZE];
    data[0] = 99;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(5, 3, data),
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
            (delegation_authority, create_funded_account(1_000_000_000)),
        ],
        &[Check::success()],
    );

    // Verify both sequences were updated
    let env: &Envelope =
        bytemuck::from_bytes(&result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()]);
    assert_eq!(env.authority_aux_sequence, 5);
    assert_eq!(env.program_aux_sequence, 3);
    assert_eq!(env.auxiliary_data[0], 99);
}
