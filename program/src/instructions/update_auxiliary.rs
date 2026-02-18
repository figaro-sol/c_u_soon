use c_u_soon::{Envelope, AUX_DATA_SIZE};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

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

    if envelope.has_delegation() {
        if !envelope
            .user_bitmask
            .apply_masked_update(&mut envelope.auxiliary_data, data)
        {
            return Err(ProgramError::InvalidArgument);
        }
    } else {
        envelope.auxiliary_data = *data;
    }

    envelope.authority_aux_sequence = sequence;

    Ok(())
}
