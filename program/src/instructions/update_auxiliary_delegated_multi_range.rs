use super::cpi_verification::verify_delegation_authority;
use bytemuck::Zeroable;
use c_u_soon::{Envelope, StructMetadata};
use c_u_soon_instruction::WriteSpec;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

/// Validate delegation accounts, envelope ownership, metadata, sequence, and delegation authority,
/// then call `apply` with the validated envelope and metadata.
fn with_validated_delegation<F>(
    program_id: &Address,
    accounts: &[AccountView],
    metadata: u64,
    sequence: u64,
    apply: F,
) -> ProgramResult
where
    F: FnOnce(&mut Envelope, StructMetadata) -> Result<(), ProgramError>,
{
    let [delegation_authority, envelope_account, _padding] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !envelope_account.owned_by(program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let meta = StructMetadata::from_raw(metadata);

    let mut envelope_data = envelope_account.try_borrow_mut()?;
    let envelope: &mut Envelope = bytemuck::from_bytes_mut(&mut envelope_data);

    if envelope.auxiliary_metadata != meta {
        return Err(ProgramError::InvalidInstructionData);
    }

    if envelope.delegation_authority == Address::zeroed() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_delegation_authority(delegation_authority, &envelope.delegation_authority)?;

    if sequence <= envelope.program_aux_sequence {
        return Err(ProgramError::InvalidInstructionData);
    }

    apply(envelope, meta)?;
    envelope.program_aux_sequence = sequence;

    Ok(())
}

/// Zero-alloc single-range write of auxiliary data as the delegated program.
///
/// Accounts: `[delegation_authority (signer), envelope_account, _padding]`.
pub fn process_single(
    program_id: &Address,
    accounts: &[AccountView],
    metadata: u64,
    sequence: u64,
    offset: u8,
    data: &[u8],
) -> ProgramResult {
    with_validated_delegation(
        program_id,
        accounts,
        metadata,
        sequence,
        |envelope, meta| {
            super::apply_ranges::validate_and_apply_single(
                &mut envelope.auxiliary_data,
                &envelope.program_bitmask,
                meta.type_size() as usize,
                offset,
                data,
            )
        },
    )
}

/// Write multiple non-contiguous byte ranges of auxiliary data as the delegated program.
///
/// Accounts: `[delegation_authority (signer), envelope_account, _padding]`.
///
/// Each range is validated against `program_bitmask` via `check_masked_update` (blocked
/// bytes are allowed as long as they're unchanged). Validate-then-apply ensures atomicity.
pub fn process(
    program_id: &Address,
    accounts: &[AccountView],
    metadata: u64,
    sequence: u64,
    ranges: Vec<WriteSpec>,
) -> ProgramResult {
    with_validated_delegation(
        program_id,
        accounts,
        metadata,
        sequence,
        |envelope, meta| {
            super::apply_ranges::validate_and_apply(
                &mut envelope.auxiliary_data,
                &envelope.program_bitmask,
                meta.type_size() as usize,
                &ranges,
            )
        },
    )
}
