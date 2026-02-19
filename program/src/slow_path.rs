use c_u_soon::Bitmask;
use c_u_soon_client_common::SlowPathInstruction;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use super::instructions;

#[cold]
#[inline(never)]
pub(crate) unsafe fn slow_entrypoint(input: *mut u8) -> u64 {
    pinocchio::entrypoint::process_entrypoint::<64>(input, process_instruction)
}

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
            &Bitmask::from(program_bitmask),
            &Bitmask::from(user_bitmask),
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
