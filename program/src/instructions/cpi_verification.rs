use pinocchio::{error::ProgramError, AccountView, Address};

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
