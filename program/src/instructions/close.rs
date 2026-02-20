use c_u_soon::Envelope;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Deallocate an oracle PDA and return its lamports to a recipient.
///
/// Accounts: `[authority (signer), envelope_account, recipient]`.
///
/// Requires no active delegation (`!envelope.has_delegation()`); close is blocked while a
/// delegated program may still hold references. Zero-fills account data before deallocation
/// to clear oracle state from on-chain storage. `recipient` must differ from `envelope_account`.
/// Transfers all lamports to `recipient`, resizes the account to 0, and reassigns ownership to
/// the system program.
pub fn process(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [authority, envelope_account, recipient] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if envelope_account.address() == recipient.address() {
        return Err(ProgramError::InvalidArgument);
    }

    if !envelope_account.owned_by(program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }

    {
        let mut envelope_data = envelope_account.try_borrow_mut()?;
        let envelope: &Envelope = bytemuck::from_bytes(&envelope_data);
        if envelope.authority != *authority.address() {
            return Err(ProgramError::IncorrectAuthority);
        }
        if envelope.has_delegation() {
            return Err(ProgramError::InvalidArgument);
        }
        envelope_data.fill(0);
    }

    let envelope_lamports = envelope_account.lamports();
    let recipient_lamports = recipient.lamports();
    envelope_account.set_lamports(0);
    recipient.set_lamports(recipient_lamports + envelope_lamports);

    envelope_account.resize(0)?;
    unsafe { envelope_account.assign(&pinocchio_system::ID) };

    Ok(())
}
