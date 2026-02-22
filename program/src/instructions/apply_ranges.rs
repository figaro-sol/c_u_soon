use c_u_soon::{Mask, AUX_DATA_SIZE};
use c_u_soon_instruction::WriteSpec;
use pinocchio::error::ProgramError;

/// Validate a single range against the mask, then apply it.
///
/// Zero-alloc path for single-range wire tags (7/8).
pub fn validate_and_apply_single(
    aux_data: &mut [u8; AUX_DATA_SIZE],
    mask: &Mask,
    type_size: usize,
    offset: u8,
    data: &[u8],
) -> Result<(), ProgramError> {
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let off = offset as usize;
    let end = off
        .checked_add(data.len())
        .ok_or(ProgramError::InvalidInstructionData)?;
    if end > type_size {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !mask.check_masked_update(aux_data, off, data) {
        return Err(ProgramError::InvalidArgument);
    }
    aux_data[off..end].copy_from_slice(data);
    Ok(())
}

/// Validate all ranges against the mask, then apply them atomically.
///
/// Phase 1: bounds checks + `check_masked_update` for every range.
/// Phase 2: copy all ranges into `aux_data`.
///
/// Returns `InvalidInstructionData` for bounds violations,
/// `InvalidArgument` if a blocked byte would be changed.
pub fn validate_and_apply(
    aux_data: &mut [u8; AUX_DATA_SIZE],
    mask: &Mask,
    type_size: usize,
    ranges: &[WriteSpec],
) -> Result<(), ProgramError> {
    // Bounds + empty checks
    for spec in ranges {
        if spec.data.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let end = (spec.offset as usize)
            .checked_add(spec.data.len())
            .ok_or(ProgramError::InvalidInstructionData)?;
        if end > type_size {
            return Err(ProgramError::InvalidInstructionData);
        }
    }

    // Phase 1: validate ALL ranges via check_masked_update
    for spec in ranges {
        if !mask.check_masked_update(aux_data, spec.offset as usize, &spec.data) {
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Phase 2: apply all
    for spec in ranges {
        let off = spec.offset as usize;
        aux_data[off..off + spec.data.len()].copy_from_slice(&spec.data);
    }

    Ok(())
}
