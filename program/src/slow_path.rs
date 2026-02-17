use c_u_soon::SlowPathInstruction;
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
        SlowPathInstruction::Create { custom_seeds, bump } => {
            instructions::create::process(program_id, accounts, custom_seeds, bump)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
