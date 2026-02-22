use c_u_soon::Mask;
use c_u_soon_instruction::{
    SlowPathInstruction, UPDATE_AUX_DELEGATED_RANGE_TAG, UPDATE_AUX_DELEGATED_TAG,
    UPDATE_AUX_FORCE_HEADER_SIZE, UPDATE_AUX_FORCE_TAG, UPDATE_AUX_HEADER_SIZE,
    UPDATE_AUX_RANGE_HEADER_SIZE, UPDATE_AUX_RANGE_TAG, UPDATE_AUX_TAG,
};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use wincode::SchemaRead;

use super::instructions;

/// Account administration entry point, reached when account count != 2.
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

/// Dispatch a slow-path instruction.
///
/// Tags 4-8 (UpdateAuxiliary variants) use a manual wire format.
/// All other tags (0-3, 9-10) use wincode deserialization with trailing-data rejection.
fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let disc = u32::from_le_bytes(data[..4].try_into().unwrap());

    match disc {
        UPDATE_AUX_TAG => {
            if data.len() < UPDATE_AUX_HEADER_SIZE {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let sequence = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let aux_data = &data[20..];
            instructions::update_auxiliary::process(
                program_id, accounts, metadata, sequence, aux_data,
            )
        }
        UPDATE_AUX_DELEGATED_TAG => {
            if data.len() < UPDATE_AUX_HEADER_SIZE {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let sequence = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let aux_data = &data[20..];
            instructions::update_auxiliary_delegated::process(
                program_id, accounts, metadata, sequence, aux_data,
            )
        }
        UPDATE_AUX_FORCE_TAG => {
            if data.len() < UPDATE_AUX_FORCE_HEADER_SIZE {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let auth_seq = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let prog_seq = u64::from_le_bytes(data[20..28].try_into().unwrap());
            let aux_data = &data[28..];
            instructions::update_auxiliary_force::process(
                program_id, accounts, metadata, auth_seq, prog_seq, aux_data,
            )
        }
        UPDATE_AUX_RANGE_TAG => {
            if data.len() < UPDATE_AUX_RANGE_HEADER_SIZE {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let sequence = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let offset = data[20];
            let range_data = &data[21..];
            instructions::update_auxiliary_multi_range::process_single(
                program_id, accounts, metadata, sequence, offset, range_data,
            )
        }
        UPDATE_AUX_DELEGATED_RANGE_TAG => {
            if data.len() < UPDATE_AUX_RANGE_HEADER_SIZE {
                return Err(ProgramError::InvalidInstructionData);
            }
            let metadata = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let sequence = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let offset = data[20];
            let range_data = &data[21..];
            instructions::update_auxiliary_delegated_multi_range::process_single(
                program_id, accounts, metadata, sequence, offset, range_data,
            )
        }
        _ => {
            // Wincode deserialization with trailing-data rejection
            let mut cursor: &[u8] = data;
            let ix = <SlowPathInstruction as SchemaRead>::get(&mut cursor)
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            if !cursor.is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            if !ix.validate() {
                return Err(ProgramError::InvalidInstructionData);
            }
            match ix {
                SlowPathInstruction::Create {
                    custom_seeds,
                    bump,
                    oracle_metadata,
                } => instructions::create::process(
                    program_id,
                    accounts,
                    custom_seeds,
                    bump,
                    oracle_metadata,
                ),
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
                SlowPathInstruction::UpdateAuxiliaryMultiRange {
                    metadata,
                    sequence,
                    ranges,
                } => instructions::update_auxiliary_multi_range::process(
                    program_id, accounts, metadata, sequence, ranges,
                ),
                SlowPathInstruction::UpdateAuxiliaryDelegatedMultiRange {
                    metadata,
                    sequence,
                    ranges,
                } => instructions::update_auxiliary_delegated_multi_range::process(
                    program_id, accounts, metadata, sequence, ranges,
                ),
            }
        }
    }
}
