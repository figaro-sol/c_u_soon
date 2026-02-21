use c_u_soon::{Envelope, StructMetadata};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Write auxiliary data as the oracle authority.
///
/// Accounts: `[authority (signer), envelope_account, pda_account (signer)]`.
///
/// `metadata` must match `envelope.auxiliary_metadata`. `data.len()` must equal
/// `metadata.type_size()`. `sequence` must be strictly greater than
/// `envelope.authority_aux_sequence` (monotonic).
///
/// Requires active delegation. `user_bitmask` gates which bytes of `auxiliary_data`
/// may be written (`0x00` = writable, `0xFF` = blocked). Returns
/// [`ProgramError::InvalidArgument`] if any blocked byte differs from the current value.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    metadata: u64,
    sequence: u64,
    data: &[u8],
) -> ProgramResult {
    let [authority, envelope_account, _pda] = accounts else {
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

    if sequence <= envelope.authority_aux_sequence {
        return Err(ProgramError::InvalidInstructionData);
    }

    if !envelope.has_delegation() {
        return Err(ProgramError::InvalidArgument);
    }

    if !envelope
        .user_bitmask
        .apply_masked_update(&mut envelope.auxiliary_data, data)
    {
        return Err(ProgramError::InvalidArgument);
    }

    envelope.authority_aux_sequence = sequence;

    Ok(())
}
