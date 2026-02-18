use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};

/// Attack instruction variants for security testing
/// Each variant attempts to violate a specific security property
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum AttackerProbeInstruction {
    /// Fast path without authority signer (should be rejected)
    FastPathWithoutAuthoritySigner { sequence: u64, payload: Vec<u8> },

    /// Fast path with wrong authority (should be rejected)
    FastPathWithWrongAuthority { sequence: u64, payload: Vec<u8> },

    /// Slow path without PDA signer when required (should be rejected)
    SlowPathWithoutPdaSigner { sequence: u64, aux_data: Vec<u8> },

    /// Slow path with wrong PDA (should be rejected)
    SlowPathWithWrongPda { sequence: u64, aux_data: Vec<u8> },

    /// Claim authority signer in metadata without actual signature (should be rejected)
    ForgedSignerMetadata { sequence: u64, payload: Vec<u8> },

    /// Reuse stale sequence number (should be rejected)
    StaleSequence { sequence: u64, payload: Vec<u8> },

    /// Send oversized payload (>255 bytes, should be rejected by fast path)
    OversizedPayload { sequence: u64, payload: Vec<u8> },

    /// Use wrong delegation authority (should be rejected)
    WrongDelegationAuthority { sequence: u64, aux_data: Vec<u8> },

    /// Attempt to spend same sequence twice (should be rejected)
    DoubleSpendSequence { sequence: u64, payload: Vec<u8> },

    /// Try to swap oracle account with different one via CPI (should be rejected)
    CrossProgramAccountSwap { sequence: u64, payload: Vec<u8> },

    /// Send undersized account (should be rejected)
    UndersizedAccount { sequence: u64, payload: Vec<u8> },

    /// Echo instruction - just return success
    Echo,
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction: AttackerProbeInstruction = borsh::from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        AttackerProbeInstruction::FastPathWithoutAuthoritySigner { sequence, payload } => {
            fast_path_without_authority_signer(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::FastPathWithWrongAuthority { sequence, payload } => {
            fast_path_with_wrong_authority(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::SlowPathWithoutPdaSigner { sequence, aux_data } => {
            slow_path_without_pda_signer(program_id, accounts, sequence, &aux_data)
        }
        AttackerProbeInstruction::SlowPathWithWrongPda { sequence, aux_data } => {
            slow_path_with_wrong_pda(program_id, accounts, sequence, &aux_data)
        }
        AttackerProbeInstruction::ForgedSignerMetadata { sequence, payload } => {
            forged_signer_metadata(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::StaleSequence { sequence, payload } => {
            stale_sequence(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::OversizedPayload { sequence, payload } => {
            oversized_payload(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::WrongDelegationAuthority { sequence, aux_data } => {
            wrong_delegation_authority(program_id, accounts, sequence, &aux_data)
        }
        AttackerProbeInstruction::DoubleSpendSequence { sequence, payload } => {
            double_spend_sequence(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::CrossProgramAccountSwap { sequence, payload } => {
            cross_program_account_swap(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::UndersizedAccount { sequence, payload } => {
            undersized_account(program_id, accounts, sequence, &payload)
        }
        AttackerProbeInstruction::Echo => Ok(()),
    }
}

fn fast_path_without_authority_signer(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    // Simulate calling fast path without authority being a signer
    msg!("ATTACK: FastPathWithoutAuthoritySigner sequence={}", sequence);
    Ok(())
}

fn fast_path_with_wrong_authority(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    msg!("ATTACK: FastPathWithWrongAuthority sequence={}", sequence);
    Ok(())
}

fn slow_path_without_pda_signer(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _aux_data: &[u8],
) -> ProgramResult {
    msg!("ATTACK: SlowPathWithoutPdaSigner sequence={}", sequence);
    Ok(())
}

fn slow_path_with_wrong_pda(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _aux_data: &[u8],
) -> ProgramResult {
    msg!("ATTACK: SlowPathWithWrongPda sequence={}", sequence);
    Ok(())
}

fn forged_signer_metadata(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    msg!("ATTACK: ForgedSignerMetadata sequence={}", sequence);
    Ok(())
}

fn stale_sequence(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    msg!("ATTACK: StaleSequence sequence={}", sequence);
    Ok(())
}

fn oversized_payload(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    msg!("ATTACK: OversizedPayload sequence={}", sequence);
    Ok(())
}

fn wrong_delegation_authority(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _aux_data: &[u8],
) -> ProgramResult {
    msg!("ATTACK: WrongDelegationAuthority sequence={}", sequence);
    Ok(())
}

fn double_spend_sequence(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    msg!("ATTACK: DoubleSpendSequence sequence={}", sequence);
    Ok(())
}

fn cross_program_account_swap(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    msg!("ATTACK: CrossProgramAccountSwap sequence={}", sequence);
    Ok(())
}

fn undersized_account(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    sequence: u64,
    _payload: &[u8],
) -> ProgramResult {
    msg!("ATTACK: UndersizedAccount sequence={}", sequence);
    Ok(())
}
