use super::cpi_verification::verify_delegation_authority;
use bytemuck::Zeroable;
use c_u_soon::{Envelope, StructMetadata};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Reset both sequence counters and overwrite auxiliary data, requiring both signers.
///
/// Accounts: `[authority (signer), envelope_account, delegation_authority (signer)]`.
///
/// `metadata` must match `envelope.auxiliary_metadata`. `data.len()` must equal
/// `metadata.type_size()`. Requires an active delegation. Both `authority` and
/// `delegation_authority` must sign.
///
/// Overwrites `auxiliary_data[..data.len()]` without bitmask enforcement and zeroes
/// trailing bytes. Sets both sequence counters simultaneously.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    metadata: u64,
    authority_sequence: u64,
    program_sequence: u64,
    data: &[u8],
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

    let meta = StructMetadata::from_raw(metadata);

    let mut envelope_data = envelope_account.try_borrow_mut()?;
    let envelope: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_data);

    if envelope.auxiliary_metadata != meta {
        return Err(ProgramError::InvalidInstructionData);
    }

    if data.len() != meta.type_size() as usize {
        return Err(ProgramError::InvalidInstructionData);
    }

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

    envelope.auxiliary_data[..data.len()].copy_from_slice(data);
    envelope.auxiliary_data[data.len()..].fill(0);
    envelope.authority_aux_sequence = authority_sequence;
    envelope.program_aux_sequence = program_sequence;

    Ok(())
}
