use c_u_soon::Mask;
use c_u_soon_instruction::SlowPathInstruction;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use super::instructions;

/// Account administration entry point, reached when account count ≠ 2.
///
/// Marked `#[cold]` and `#[inline(never)]` because this path is taken rarely relative to the
/// fast path. Allocates stack for up to 64 accounts via `process_entrypoint::<64>`.
///
/// # Safety
///
/// `input` must be the Solana runtime's serialized account blob.
#[cold]
#[inline(never)]
pub(crate) unsafe fn slow_entrypoint(input: *mut u8) -> u64 {
    pinocchio::entrypoint::process_entrypoint::<64>(input, process_instruction)
}

/// Deserialize and dispatch a [`SlowPathInstruction`].
///
/// Returns [`ProgramError::InvalidInstructionData`] if `wincode` deserialization fails or
/// `ix.validate()` returns false. `validate()` checks structural invariants (seed counts,
/// seed lengths, mask canonicality) before the handler runs.
fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: SlowPathInstruction =
        wincode::deserialize(data).map_err(|_| ProgramError::InvalidInstructionData)?;

    if !ix.validate() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match ix {
        SlowPathInstruction::Create {
            custom_seeds,
            bump,
            oracle_metadata,
        } => {
            instructions::create::process(program_id, accounts, custom_seeds, bump, oracle_metadata)
        }
        SlowPathInstruction::Close => instructions::close::process(program_id, accounts),
        SlowPathInstruction::SetDelegatedProgram {
            program_bitmask,
            user_bitmask,
        } => instructions::set_delegated_program::process(
            program_id,
            accounts,
            &Mask::from(program_bitmask),
            &Mask::from(user_bitmask),
        ),
        SlowPathInstruction::ClearDelegation => {
            instructions::clear_delegation::process(program_id, accounts)
        }
        SlowPathInstruction::UpdateAuxiliary { sequence, data } => {
            instructions::update_auxiliary::process(program_id, accounts, sequence, &data)
        }
        SlowPathInstruction::UpdateAuxiliaryDelegated { sequence, data } => {
            instructions::update_auxiliary_delegated::process(program_id, accounts, sequence, &data)
        }
        SlowPathInstruction::UpdateAuxiliaryForce {
            authority_sequence,
            program_sequence,
            data,
        } => instructions::update_auxiliary_force::process(
            program_id,
            accounts,
            authority_sequence,
            program_sequence,
            &data,
        ),
    }
}
