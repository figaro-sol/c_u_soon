//! Instruction data builders for the c_u_soon oracle program.
//!
//! Fast-path functions ([`fast_path_instruction_data`], [`fast_path_update_typed`]) build
//! compact oracle update bytes sent directly to the program entry point. Slow-path functions
//! serialize a [`SlowPathInstruction`] variant via `wincode` and cover account administration:
//! create, close, delegation, and auxiliary writes.
//!
//! All functions return `Vec<u8>` to pass as transaction instruction data. The `_typed`
//! variants take a `T: TypeHash` and read `T::METADATA` so you don't pass it manually.

use c_u_soon::{Mask, StructMetadata, TypeHash, AUX_DATA_SIZE, MAX_CUSTOM_SEEDS, ORACLE_BYTES};
use c_u_soon_instruction::SlowPathInstruction;

/// Errors returned by instruction builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionError {
    /// Payload exceeds [`ORACLE_BYTES`] (239) bytes.
    PayloadTooLarge,
    /// `custom_seeds` has more than [`MAX_CUSTOM_SEEDS`] (13) entries.
    TooManySeeds,
    /// A seed is longer than 32 bytes.
    SeedTooLong,
    /// A mask byte is not `0x00` (writable) or `0xFF` (blocked).
    NonCanonicalMask,
    /// `wincode` serialization failed. Should not happen for valid inputs.
    SerializationFailed,
}

impl core::fmt::Display for InstructionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "payload exceeds {} bytes", ORACLE_BYTES),
            Self::TooManySeeds => write!(f, "more than {} custom seeds", MAX_CUSTOM_SEEDS),
            Self::SeedTooLong => write!(f, "seed exceeds 32 bytes"),
            Self::NonCanonicalMask => write!(f, "mask byte not 0x00 or 0xFF"),
            Self::SerializationFailed => write!(f, "wincode serialization failed"),
        }
    }
}

impl std::error::Error for InstructionError {}

/// Build fast-path instruction data: `[oracle_meta: u64 LE | sequence: u64 LE | payload]`.
///
/// - `oracle_meta`: packed [`StructMetadata`] identifying the oracle's auxiliary type schema.
///   Use `T::METADATA.as_u64()` or the typed wrapper [`fast_path_update_typed`].
/// - `sequence`: monotonic authority sequence counter. Must match the oracle's current value;
///   the program rejects stale or reused sequences to prevent replay.
/// - `payload`: raw bytes to write into the oracle data slot (≤ [`ORACLE_BYTES`] = 239 bytes).
///
/// Returns [`InstructionError::PayloadTooLarge`] if `payload.len() > ORACLE_BYTES`.
pub fn fast_path_instruction_data(
    oracle_meta: u64,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>, InstructionError> {
    if payload.len() > ORACLE_BYTES {
        return Err(InstructionError::PayloadTooLarge);
    }
    let mut data = Vec::with_capacity(8 + 8 + payload.len());
    data.extend_from_slice(&oracle_meta.to_le_bytes());
    data.extend_from_slice(&sequence.to_le_bytes());
    data.extend_from_slice(payload);
    Ok(data)
}

/// Serialize a `Create` instruction (slow path): initialize an oracle PDA.
///
/// - `custom_seeds`: up to [`MAX_CUSTOM_SEEDS`] (13) seeds, each ≤ 32 bytes.
///   Together with `bump` they identify the oracle's PDA address on-chain.
/// - `bump`: the canonical PDA bump returned by `find_program_address`.
/// - `oracle_metadata`: packed [`StructMetadata`] for the auxiliary type stored in this oracle.
///   Use `T::METADATA` or the typed wrapper [`create_envelope_typed`].
///
/// Returns [`InstructionError::TooManySeeds`] or [`InstructionError::SeedTooLong`] on bad inputs.
pub fn create_instruction_data(
    custom_seeds: &[&[u8]],
    bump: u8,
    oracle_metadata: StructMetadata,
) -> Result<Vec<u8>, InstructionError> {
    if custom_seeds.len() > MAX_CUSTOM_SEEDS {
        return Err(InstructionError::TooManySeeds);
    }
    for seed in custom_seeds {
        if seed.len() > 32 {
            return Err(InstructionError::SeedTooLong);
        }
    }
    let seeds_vecs: Vec<Vec<u8>> = custom_seeds.iter().map(|s| s.to_vec()).collect();
    let ix = SlowPathInstruction::Create {
        custom_seeds: seeds_vecs,
        bump,
        oracle_metadata: oracle_metadata.as_u64(),
    };
    wincode::serialize(&ix).map_err(|_| InstructionError::SerializationFailed)
}

/// Serialize a `Close` instruction (slow path): deallocate the oracle account.
///
/// Blocked on-chain if delegation is active. Lamports are returned to the authority.
pub fn close_instruction_data() -> Result<Vec<u8>, InstructionError> {
    wincode::serialize(&SlowPathInstruction::Close)
        .map_err(|_| InstructionError::SerializationFailed)
}

fn validate_mask_canonical(mask: &Mask) -> Result<(), InstructionError> {
    if !mask.as_bytes().iter().all(|&b| b == 0x00 || b == 0xFF) {
        return Err(InstructionError::NonCanonicalMask);
    }
    Ok(())
}

/// Serialize a `SetDelegatedProgram` instruction (slow path): assign write permissions to a delegate.
///
/// - `program_bitmask`: bytes the delegated program may write (`0x00` = writable, `0xFF` = blocked).
/// - `user_bitmask`: bytes the oracle authority may write while delegation is active.
///
/// Both masks must be canonical: every byte must be exactly `0x00` or `0xFF`.
/// Returns [`InstructionError::NonCanonicalMask`] otherwise.
pub fn set_delegated_program_instruction_data(
    program_bitmask: Mask,
    user_bitmask: Mask,
) -> Result<Vec<u8>, InstructionError> {
    validate_mask_canonical(&program_bitmask)?;
    validate_mask_canonical(&user_bitmask)?;
    wincode::serialize(&SlowPathInstruction::SetDelegatedProgram {
        program_bitmask: program_bitmask.into(),
        user_bitmask: user_bitmask.into(),
    })
    .map_err(|_| InstructionError::SerializationFailed)
}

/// Serialize a `ClearDelegation` instruction (slow path): remove the delegated program.
///
/// Zeroes the oracle state and auxiliary data on-chain.
pub fn clear_delegation_instruction_data() -> Result<Vec<u8>, InstructionError> {
    wincode::serialize(&SlowPathInstruction::ClearDelegation)
        .map_err(|_| InstructionError::SerializationFailed)
}

/// Serialize an `UpdateAuxiliary` instruction (slow path): authority writes the full aux buffer.
///
/// `sequence` must match the oracle's current authority sequence counter.
/// The program rejects the instruction if it does not match.
pub fn update_auxiliary_instruction_data(
    sequence: u64,
    data: [u8; AUX_DATA_SIZE],
) -> Result<Vec<u8>, InstructionError> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliary { sequence, data })
        .map_err(|_| InstructionError::SerializationFailed)
}

/// Serialize an `UpdateAuxiliaryForce` instruction (slow path): authority resets both sequence counters and writes aux data.
///
/// Sets the oracle's authority and program sequence counters to `authority_sequence` and
/// `program_sequence` respectively, bypassing the normal match check. Use this to recover
/// when the two counters have drifted out of sync.
pub fn update_auxiliary_force_instruction_data(
    authority_sequence: u64,
    program_sequence: u64,
    data: [u8; AUX_DATA_SIZE],
) -> Result<Vec<u8>, InstructionError> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliaryForce {
        authority_sequence,
        program_sequence,
        data,
    })
    .map_err(|_| InstructionError::SerializationFailed)
}

/// Serialize an `UpdateAuxiliaryDelegated` instruction (slow path): delegated program writes aux data.
///
/// `sequence` must match the oracle's current program sequence counter.
/// The program rejects the instruction if the caller is not the registered delegated program.
pub fn update_auxiliary_delegated_instruction_data(
    sequence: u64,
    data: [u8; AUX_DATA_SIZE],
) -> Result<Vec<u8>, InstructionError> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliaryDelegated { sequence, data })
        .map_err(|_| InstructionError::SerializationFailed)
}

/// Typed `Create`: derives oracle metadata from `T::METADATA` at compile time.
///
/// Emits a compile-time assertion that `size_of::<T>() <= ORACLE_BYTES`.
/// Otherwise identical to [`create_instruction_data`].
pub fn create_envelope_typed<T: TypeHash>(
    custom_seeds: &[&[u8]],
    bump: u8,
) -> Result<Vec<u8>, InstructionError> {
    const { assert!(core::mem::size_of::<T>() <= ORACLE_BYTES) };
    create_instruction_data(custom_seeds, bump, T::METADATA)
}

/// Typed fast-path update: serializes `value` as oracle payload using `T::METADATA`.
///
/// Casts `value` to bytes via `bytemuck::bytes_of`. Emits a compile-time assertion that
/// `size_of::<T>() <= ORACLE_BYTES`. Otherwise identical to [`fast_path_instruction_data`].
pub fn fast_path_update_typed<T: TypeHash>(
    sequence: u64,
    value: &T,
) -> Result<Vec<u8>, InstructionError> {
    const { assert!(core::mem::size_of::<T>() <= ORACLE_BYTES) };
    fast_path_instruction_data(T::METADATA.as_u64(), sequence, bytemuck::bytes_of(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use c_u_soon::MASK_SIZE;

    #[test]
    fn typed_create_matches_untyped() {
        let seeds: &[&[u8]] = &[b"test"];
        let typed = create_envelope_typed::<u32>(seeds, 42).unwrap();
        let untyped = create_instruction_data(seeds, 42, u32::METADATA).unwrap();
        assert_eq!(typed, untyped);
    }

    #[test]
    fn typed_fast_path_matches_untyped() {
        let value: u32 = 0xDEAD_BEEF;
        let typed = fast_path_update_typed::<u32>(7, &value).unwrap();
        let untyped =
            fast_path_instruction_data(u32::METADATA.as_u64(), 7, bytemuck::bytes_of(&value))
                .unwrap();
        assert_eq!(typed, untyped);
    }

    #[test]
    fn typed_fast_path_roundtrip() {
        let value: u64 = 0x1234_5678_9ABC_DEF0;
        let data = fast_path_update_typed::<u64>(99, &value).unwrap();
        assert_eq!(data.len(), 8 + 8 + 8);
        let meta = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let seq = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let payload: u64 = *bytemuck::from_bytes(&data[16..24]);
        assert_eq!(meta, u64::METADATA.as_u64());
        assert_eq!(seq, 99);
        assert_eq!(payload, value);
    }

    #[test]
    fn fast_path_rejects_oversized_payload() {
        let big = [0u8; ORACLE_BYTES + 1];
        assert_eq!(
            fast_path_instruction_data(0, 1, &big),
            Err(InstructionError::PayloadTooLarge)
        );
    }

    #[test]
    fn fast_path_accepts_max_payload() {
        let max = [0u8; ORACLE_BYTES];
        assert!(fast_path_instruction_data(0, 1, &max).is_ok());
    }

    #[test]
    fn create_rejects_too_many_seeds() {
        let seeds: Vec<&[u8]> = (0..14).map(|_| b"x" as &[u8]).collect();
        assert_eq!(
            create_instruction_data(&seeds, 0, u32::METADATA),
            Err(InstructionError::TooManySeeds)
        );
    }

    #[test]
    fn create_rejects_long_seed() {
        let long = [0u8; 33];
        let seeds: &[&[u8]] = &[&long];
        assert_eq!(
            create_instruction_data(seeds, 0, u32::METADATA),
            Err(InstructionError::SeedTooLong)
        );
    }

    #[test]
    fn set_delegation_rejects_non_canonical_mask() {
        let mut bad = [0x00u8; MASK_SIZE];
        bad[5] = 0x42;
        assert_eq!(
            set_delegated_program_instruction_data(Mask::from(bad), Mask::ALL_BLOCKED),
            Err(InstructionError::NonCanonicalMask)
        );
    }

    #[test]
    fn set_delegation_accepts_canonical_masks() {
        assert!(
            set_delegated_program_instruction_data(Mask::ALL_WRITABLE, Mask::ALL_BLOCKED).is_ok()
        );
    }
}
