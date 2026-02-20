use super::cpi_verification::verify_delegation_authority;
use bytemuck::Zeroable;
use c_u_soon::{Envelope, AUX_DATA_SIZE};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Write auxiliary data as the delegated program.
///
/// Accounts: `[envelope_account, delegation_authority (signer), _padding]`.
///
/// Requires an active delegation. `delegation_authority` must sign and match
/// `envelope.delegation_authority`. `sequence` must be strictly greater than
/// `envelope.program_aux_sequence`. The authority account is absent; only the delegated
/// program signs.
///
/// `program_bitmask` gates which bytes of `auxiliary_data` may be written (`0x00` = writable,
/// `0xFF` = blocked). Returns [`ProgramError::InvalidArgument`] if any blocked byte differs.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    sequence: u64,
    data: &[u8; AUX_DATA_SIZE],
) -> ProgramResult {
    let [delegation_authority, envelope_account, _padding] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !envelope_account.owned_by(program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let mut envelope_data = envelope_account.try_borrow_mut()?;
    let envelope: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_data);

    if envelope.delegation_authority == Address::zeroed() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_delegation_authority(delegation_authority, &envelope.delegation_authority)?;

    if sequence <= envelope.program_aux_sequence {
        return Err(ProgramError::InvalidInstructionData);
    }

    if !envelope
        .program_bitmask
        .apply_masked_update(&mut envelope.auxiliary_data, data)
    {
        return Err(ProgramError::InvalidArgument);
    }

    envelope.program_aux_sequence = sequence;

    Ok(())
}
