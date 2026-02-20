extern crate alloc;
use crate::pda::create_program_address;
use alloc::vec::Vec;
use c_u_soon::{Envelope, Mask, StructMetadata, ENVELOPE_SEED};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::Sysvar,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};

/// Initialize an oracle PDA account.
///
/// Accounts (minimum 3): `[authority (signer), envelope_account, system_program_account, ...]`.
///
/// PDA seeds: `[ENVELOPE_SEED, authority_address, ...custom_seeds, bump]`. The computed address
/// must match `envelope_account`; otherwise returns [`ProgramError::InvalidSeeds`].
///
/// Idempotent: if the envelope is already owned by this program with matching `authority`, `bump`,
/// and `oracle_metadata`, returns `Ok(())` without touching the account.
///
/// For a new account the CPI sequence is:
/// 1. `Transfer`: top up lamports to the rent-exempt minimum if needed.
/// 2. `Allocate`: set account data length to `size_of::<Envelope>()`.
/// 3. `Assign`: transfer ownership to this program.
///
/// Initializes `authority`, `bump`, and `oracle_metadata`. Both bitmasks start as `ALL_BLOCKED`.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    custom_seeds: Vec<Vec<u8>>,
    bump: u8,
    oracle_metadata: u64,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let envelope_account = &accounts[1];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let custom_seeds_refs: Vec<&[u8]> = custom_seeds.iter().map(|s| s.as_slice()).collect();
    let bump_bytes = [bump];

    let mut seeds_vec: Vec<&[u8]> = Vec::with_capacity(3 + custom_seeds_refs.len());
    seeds_vec.push(ENVELOPE_SEED);
    seeds_vec.push(authority.address().as_array().as_ref());
    seeds_vec.extend(custom_seeds_refs.iter().copied());
    seeds_vec.push(&bump_bytes);

    let expected = create_program_address(&seeds_vec, program_id)?;
    if envelope_account.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }

    // Idempotent: if envelope already exists with correct authority/bump, succeed
    if envelope_account.owned_by(program_id) {
        let envelope_data = envelope_account.try_borrow()?;
        let envelope: &Envelope = bytemuck::from_bytes(&envelope_data);
        if envelope.authority != *authority.address() {
            return Err(ProgramError::IncorrectAuthority);
        }
        if envelope.bump != bump {
            return Err(ProgramError::InvalidSeeds);
        }
        if envelope.oracle_state.oracle_metadata != StructMetadata::from_raw(oracle_metadata) {
            return Err(ProgramError::InvalidInstructionData);
        }
        return Ok(());
    }

    if !envelope_account.owned_by(&pinocchio_system::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if envelope_account.data_len() != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    let rent_exempt_lamports =
        pinocchio::sysvars::rent::Rent::get()?.try_minimum_balance(Envelope::SIZE)?;
    let current_lamports = envelope_account.lamports();

    if current_lamports < rent_exempt_lamports {
        Transfer {
            from: authority,
            to: envelope_account,
            lamports: rent_exempt_lamports - current_lamports,
        }
        .invoke()?;
    }

    let seeds_for_signer: Vec<Seed> = seeds_vec.iter().map(|s| Seed::from(*s)).collect();
    let signer = Signer::from(seeds_for_signer.as_slice());

    Allocate {
        account: envelope_account,
        space: Envelope::SIZE as u64,
    }
    .invoke_signed(core::slice::from_ref(&signer))?;

    Assign {
        account: envelope_account,
        owner: program_id,
    }
    .invoke_signed(core::slice::from_ref(&signer))?;

    let mut envelope_data = envelope_account.try_borrow_mut()?;
    let envelope: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_data);
    envelope.authority = *authority.address();
    envelope.bump = bump;
    envelope.program_bitmask = Mask::ALL_BLOCKED;
    envelope.user_bitmask = Mask::ALL_BLOCKED;
    envelope.auxiliary_metadata = StructMetadata::ZERO;
    envelope.oracle_state.oracle_metadata = StructMetadata::from_raw(oracle_metadata);

    Ok(())
}
