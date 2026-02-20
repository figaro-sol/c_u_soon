use super::cpi_verification::verify_delegation_authority;
use bytemuck::Zeroable;
use c_u_soon::{Envelope, AUX_DATA_SIZE};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Reset both sequence counters and overwrite auxiliary data, requiring both signers.
///
/// Accounts: `[authority (signer), envelope_account, delegation_authority (signer)]`.
///
/// Requires an active delegation. Both `authority` and `delegation_authority` must sign.
/// `authority_sequence` must exceed `envelope.authority_aux_sequence` and `program_sequence`
/// must exceed `envelope.program_aux_sequence` (both still monotonic).
///
/// Overwrites `auxiliary_data` in full without bitmask enforcement and sets both sequence
/// counters simultaneously. Use when the two counters have drifted out of sync.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    authority_sequence: u64,
    program_sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
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

    if envelope.authority != *authority.address() {
        return Err(ProgramError::IncorrectAuthority);
    }

    if envelope.delegation_authority == Address::zeroed() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_delegation_authority(delegation_authority, &envelope.delegation_authority)?;

    if authority_sequence <= envelope.authority_aux_sequence {
        return Err(ProgramError::InvalidInstructionData);
    }

    if program_sequence <= envelope.program_aux_sequence {
        return Err(ProgramError::InvalidInstructionData);
    }

    envelope.auxiliary_data = *data;
    envelope.authority_aux_sequence = authority_sequence;
    envelope.program_aux_sequence = program_sequence;

    Ok(())
}
