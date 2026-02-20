use super::cpi_verification::verify_delegation_authority;
use bytemuck::Zeroable;
use c_u_soon::{Envelope, Mask, OracleState, StructMetadata};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Remove delegation and wipe the oracle envelope to a clean state.
///
/// Accounts: `[authority (signer), envelope_account, delegation_authority (signer)]`.
///
/// Requires an active delegation (`envelope.delegation_authority != zeroed`).
/// `delegation_authority` must sign and match `envelope.delegation_authority`.
///
/// Zeroes `oracle_state`, `auxiliary_data`, and `auxiliary_metadata`. Resets both bitmasks to
/// `ALL_BLOCKED`. The authority may install a new delegation after this call.
pub fn process(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
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

    if envelope.delegation_authority == Address::zeroed() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_delegation_authority(delegation_authority, &envelope.delegation_authority)?;

    envelope.delegation_authority = Address::zeroed();
    envelope.program_bitmask = Mask::ALL_BLOCKED;
    envelope.user_bitmask = Mask::ALL_BLOCKED;
    envelope.oracle_state = OracleState::zeroed();
    envelope.auxiliary_data = [0u8; 256];
    envelope.auxiliary_metadata = StructMetadata::ZERO;

    Ok(())
}
