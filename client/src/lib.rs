use c_u_soon::{Bitmask, StructMetadata, TypeHash, AUX_DATA_SIZE};
use c_u_soon_client_common::SlowPathInstruction;

/// Build fast path instruction data: `[meta:8][seq:8][payload]`.
pub fn fast_path_instruction_data(oracle_meta: u64, sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 8 + payload.len());
    data.extend_from_slice(&oracle_meta.to_le_bytes());
    data.extend_from_slice(&sequence.to_le_bytes());
    data.extend_from_slice(payload);
    data
}

/// Serialize a Create instruction (slow path).
pub fn create_instruction_data(
    custom_seeds: &[&[u8]],
    bump: u8,
    oracle_metadata: StructMetadata,
) -> Vec<u8> {
    let seeds_vecs: Vec<Vec<u8>> = custom_seeds.iter().map(|s| s.to_vec()).collect();
    let ix = SlowPathInstruction::Create {
        custom_seeds: seeds_vecs,
        bump,
        oracle_metadata: oracle_metadata.0,
    };
    wincode::serialize(&ix).unwrap()
}

/// Serialize a Close instruction (slow path).
pub fn close_instruction_data() -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::Close).unwrap()
}

/// Serialize a SetDelegatedProgram instruction (slow path).
pub fn set_delegated_program_instruction_data(
    program_bitmask: Bitmask,
    user_bitmask: Bitmask,
) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::SetDelegatedProgram {
        program_bitmask: program_bitmask.into(),
        user_bitmask: user_bitmask.into(),
    })
    .unwrap()
}

/// Serialize a ClearDelegation instruction (slow path).
pub fn clear_delegation_instruction_data() -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::ClearDelegation).unwrap()
}

/// Serialize an UpdateAuxiliary instruction (slow path, authority writes).
pub fn update_auxiliary_instruction_data(sequence: u64, data: [u8; AUX_DATA_SIZE]) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliary { sequence, data }).unwrap()
}

/// Serialize an UpdateAuxiliaryForce instruction (slow path, authority overrides both seqs).
pub fn update_auxiliary_force_instruction_data(
    authority_sequence: u64,
    program_sequence: u64,
    data: [u8; AUX_DATA_SIZE],
) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliaryForce {
        authority_sequence,
        program_sequence,
        data,
    })
    .unwrap()
}

/// Serialize an UpdateAuxiliaryDelegated instruction (slow path, delegation program writes).
pub fn update_auxiliary_delegated_instruction_data(
    sequence: u64,
    data: [u8; AUX_DATA_SIZE],
) -> Vec<u8> {
    wincode::serialize(&SlowPathInstruction::UpdateAuxiliaryDelegated { sequence, data }).unwrap()
}

/// Typed Create: uses `T::METADATA` as oracle metadata.
pub fn create_envelope_typed<T: TypeHash>(custom_seeds: &[&[u8]], bump: u8) -> Vec<u8> {
    create_instruction_data(custom_seeds, bump, T::METADATA)
}

/// Typed fast path: serializes `value` as oracle payload with `T::METADATA`.
pub fn fast_path_update_typed<T: TypeHash>(sequence: u64, value: &T) -> Vec<u8> {
    fast_path_instruction_data(T::METADATA.0, sequence, bytemuck::bytes_of(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_create_matches_untyped() {
        let seeds: &[&[u8]] = &[b"test"];
        let typed = create_envelope_typed::<u32>(seeds, 42);
        let untyped = create_instruction_data(seeds, 42, u32::METADATA);
        assert_eq!(typed, untyped);
    }

    #[test]
    fn typed_fast_path_matches_untyped() {
        let value: u32 = 0xDEAD_BEEF;
        let typed = fast_path_update_typed::<u32>(7, &value);
        let untyped = fast_path_instruction_data(u32::METADATA.0, 7, bytemuck::bytes_of(&value));
        assert_eq!(typed, untyped);
    }

    #[test]
    fn typed_fast_path_roundtrip() {
        let value: u64 = 0x1234_5678_9ABC_DEF0;
        let data = fast_path_update_typed::<u64>(99, &value);
        assert_eq!(data.len(), 8 + 8 + 8);
        let meta = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let seq = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let payload: u64 = *bytemuck::from_bytes(&data[16..24]);
        assert_eq!(meta, u64::METADATA.0);
        assert_eq!(seq, 99);
        assert_eq!(payload, value);
    }
}
