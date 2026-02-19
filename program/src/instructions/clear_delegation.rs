use super::cpi_verification::verify_delegation_authority;
use bytemuck::Zeroable;
use c_u_soon::{Bitmask, Envelope, OracleState, StructMetadata};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

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
    envelope.program_bitmask = Bitmask::ZERO;
    envelope.user_bitmask = Bitmask::ZERO;
    envelope.oracle_state = OracleState::zeroed();
    envelope.auxiliary_data = [0u8; 256];
    envelope.auxiliary_metadata = StructMetadata::ZERO;

    Ok(())
}
