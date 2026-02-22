use super::cpi_verification::verify_delegation_authority;
use bytemuck::Zeroable;
use c_u_soon::{Envelope, StructMetadata};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Write auxiliary data as the delegated program.
///
/// Accounts: `[delegation_authority (signer), envelope_account, _padding]`.
///
/// The third account is padding to keep this a 3-account instruction so the
/// fast path (which intercepts all 2-account instructions) doesn't misroute it.
///
/// `metadata` must match `envelope.auxiliary_metadata`. `data.len()` must equal
/// `metadata.type_size()`. Requires an active delegation. `delegation_authority`
/// must sign and match `envelope.delegation_authority`. `sequence` must be strictly
/// greater than `envelope.program_aux_sequence`.
///
/// `program_bitmask` gates which bytes of `auxiliary_data` may be written (`0x00` = writable,
/// `0xFF` = blocked). Returns [`ProgramError::InvalidArgument`] if any blocked byte differs.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    metadata: u64,
    sequence: u64,
    data: &[u8],
) -> ProgramResult {
    let [delegation_authority, envelope_account, _padding] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

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

    if envelope.delegation_authority == Address::zeroed() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_delegation_authority(delegation_authority, &envelope.delegation_authority)?;

    if sequence <= envelope.program_aux_sequence {
        return Err(ProgramError::InvalidInstructionData);
    }

    if !envelope
        .program_bitmask
        .apply_masked_update(&mut envelope.auxiliary_data, 0, data)
    {
        return Err(ProgramError::InvalidArgument);
    }

    envelope.program_aux_sequence = sequence;

    Ok(())
}
