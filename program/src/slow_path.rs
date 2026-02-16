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
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    match data[0] {
        0 => instructions::create::process(program_id, accounts, &data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
