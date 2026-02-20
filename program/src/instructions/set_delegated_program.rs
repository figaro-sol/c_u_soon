use bytemuck::Zeroable;
use c_u_soon::{Envelope, Mask};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Assign a delegated program and write-access bitmasks to an oracle envelope.
///
/// Accounts: `[authority (signer), envelope_account, delegation_authority (signer)]`.
///
/// Requires no active delegation (`envelope.delegation_authority == zeroed`); both bitmasks
/// must already be `ALL_BLOCKED`. This prevents overwriting an existing delegation without
/// going through [`clear_delegation`] first.
/// `delegation_authority` must be non-zero and must sign the transaction.
///
/// Sets `envelope.delegation_authority`, `program_bitmask`, and `user_bitmask`.
///
/// [`clear_delegation`]: super::clear_delegation::process
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    program_bitmask: &Mask,
    user_bitmask: &Mask,
) -> ProgramResult {
    let [authority, envelope_account, delegation_authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !envelope_account.owned_by(program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut envelope_data = envelope_account.try_borrow_mut()?;
    let envelope: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_data);

    if &envelope.authority != authority.address() {
        return Err(ProgramError::IncorrectAuthority);
    }

    if envelope.delegation_authority != Address::zeroed() {
        return Err(ProgramError::InvalidArgument);
    }

    if !envelope.program_bitmask.is_all_blocked() || !envelope.user_bitmask.is_all_blocked() {
        return Err(ProgramError::InvalidAccountData);
    }

    if !delegation_authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if delegation_authority.address() == &Address::zeroed() {
        return Err(ProgramError::InvalidAccountData);
    }

    envelope.delegation_authority = *delegation_authority.address();
    envelope.program_bitmask = *program_bitmask;
    envelope.user_bitmask = *user_bitmask;

    Ok(())
}
