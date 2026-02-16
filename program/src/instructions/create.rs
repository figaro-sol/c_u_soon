use crate::pda::create_program_address;
use c_u_soon::{parse_seeds, Envelope, ENVELOPE_SEED, MAX_CUSTOM_SEEDS};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::Sysvar,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};

// ENVELOPE_SEED + authority + up to MAX_CUSTOM_SEEDS + bump
const MAX_SEEDS: usize = 2 + MAX_CUSTOM_SEEDS + 1;

pub fn process(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    let envelope_account = &accounts[1];
    // accounts[2] = system_program (found by ID during CPI)
    // accounts[3..] = padding, ignored

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (parser, bump) = parse_seeds(data).ok_or(ProgramError::InvalidInstructionData)?;

    // Build seeds array on stack: [ENVELOPE_SEED, authority, custom_seeds..., bump]
    let bump_bytes = [bump];
    let mut seed_storage: [&[u8]; MAX_SEEDS] = [&[]; MAX_SEEDS];
    seed_storage[0] = ENVELOPE_SEED;
    seed_storage[1] = authority.address().as_array().as_ref();
    let mut idx = 2;
    for seed in parser {
        seed_storage[idx] = seed;
        idx += 1;
    }
    seed_storage[idx] = &bump_bytes;
    let seeds = &seed_storage[..idx + 1];

    let expected = create_program_address(seeds, program_id)?;
    if envelope_account.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }

    // Idempotent: if envelope already exists with correct authority, succeed
    if envelope_account.owned_by(program_id) {
        let envelope_data = envelope_account.try_borrow()?;
        let envelope: &Envelope = bytemuck::from_bytes(&envelope_data);
        if envelope.authority != *authority.address() {
            return Err(ProgramError::IncorrectAuthority);
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

    // Build CPI signer from the same seeds slice
    let mut cpi_seeds: [core::mem::MaybeUninit<Seed>; MAX_SEEDS] =
        unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    for (i, s) in seeds.iter().enumerate() {
        cpi_seeds[i].write(Seed::from(*s));
    }
    let num_seeds = seeds.len();
    let cpi_seeds_init =
        unsafe { core::slice::from_raw_parts(cpi_seeds.as_ptr() as *const Seed, num_seeds) };
    let signer = Signer::from(cpi_seeds_init);

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

    Ok(())
}
