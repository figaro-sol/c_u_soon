use c_u_soon::{Envelope, AUX_DATA_SIZE};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Write auxiliary data as the oracle authority.
///
/// Accounts: `[authority (signer), envelope_account, pda_account]`.
///
/// `sequence` must be strictly greater than `envelope.authority_aux_sequence` (monotonic).
///
/// When delegation is active, `pda_account` is ignored and `user_bitmask` gates which bytes of
/// `auxiliary_data` may be written (`0x00` = writable, `0xFF` = blocked). Returns
/// [`ProgramError::InvalidArgument`] if any blocked byte differs from the current value.
///
/// When delegation is inactive, `pda_account` must sign and the full `auxiliary_data` is overwritten.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    let [authority, envelope_account, _padding] = accounts else {
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
