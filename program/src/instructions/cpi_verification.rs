use pinocchio::{error::ProgramError, AccountView, Address};

/// Confirm that `delegation_authority` is a signer and its address matches `expected`.
///
/// Returns [`ProgramError::MissingRequiredSignature`] if the account has not signed, or
/// [`ProgramError::IncorrectAuthority`] if the address does not match `expected`.
///
/// Called by `clear_delegation`, `update_auxiliary_delegated`, and `update_auxiliary_force`
/// before mutating the envelope.
pub fn verify_delegation_authority(
    delegation_authority: &AccountView,
    expected: &Address,
) -> Result<(), ProgramError> {
    if !delegation_authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if delegation_authority.address() != expected {
        return Err(ProgramError::IncorrectAuthority);
    }
    Ok(())
}
