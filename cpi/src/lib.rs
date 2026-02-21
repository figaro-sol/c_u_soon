#![no_std]
//! CPI helpers for invoking the c_u_soon oracle program from another Solana program.
//!
//! Each struct assembles instruction data and accounts, then provides
//! `invoke()` and `invoke_signed()` methods following the pinocchio convention.

use c_u_soon::{AUX_DATA_SIZE, ORACLE_BYTES};
use c_u_soon_instruction::{
    SlowPathInstruction, UPDATE_AUX_FORCE_SERIALIZED_SIZE, UPDATE_AUX_SERIALIZED_SIZE,
};
use pinocchio::{
    cpi::{invoke, invoke_signed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

const FAST_PATH_MAX: usize = 8 + 8 + ORACLE_BYTES; // 255

/// CPI: fast path oracle update.
///
/// Instruction data: `[oracle_meta: u64 LE | sequence: u64 LE | payload: ...]`
///
/// Account order: `[authority (readonly signer), envelope (writable)]`
pub struct FastPathUpdate<'a> {
    pub authority: &'a AccountView,
    pub envelope: &'a AccountView,
    pub program: &'a AccountView,
    pub oracle_meta: u64,
    pub sequence: u64,
    pub payload: &'a [u8],
}

impl FastPathUpdate<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        if self.payload.len() > ORACLE_BYTES {
            return Err(ProgramError::InvalidInstructionData);
        }
        let payload_len = self.payload.len();
        let mut buf = [0u8; FAST_PATH_MAX];
        buf[..8].copy_from_slice(&self.oracle_meta.to_le_bytes());
        buf[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        buf[16..16 + payload_len].copy_from_slice(&self.payload[..payload_len]);

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.authority.address()),
            InstructionAccount::writable(self.envelope.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf[..16 + payload_len],
        };
        invoke_signed(&ix, &[self.authority, self.envelope], signers)
    }
}

/// CPI: UpdateAuxiliary (authority writes aux data).
///
/// Account order: `[authority (readonly signer), envelope (writable), pda (readonly signer)]`
///
/// `pda` is the caller's PDA; the oracle program verifies it as a signer to confirm
/// the call's origin.
pub struct UpdateAuxiliary<'a> {
    pub authority: &'a AccountView,
    pub envelope: &'a AccountView,
    pub pda: &'a AccountView,
    pub program: &'a AccountView,
    pub sequence: u64,
    pub data: &'a [u8; AUX_DATA_SIZE],
}

impl UpdateAuxiliary<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let ix_enum = SlowPathInstruction::UpdateAuxiliary {
            sequence: self.sequence,
            data: *self.data,
        };
        let mut buf = [0u8; UPDATE_AUX_SERIALIZED_SIZE];
        wincode::serialize_into(&mut &mut buf[..], &ix_enum)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.authority.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly_signer(self.pda.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf,
        };
        invoke_signed(&ix, &[self.authority, self.envelope, self.pda], signers)
    }
}

/// CPI: UpdateAuxiliaryDelegated (delegated program writes aux data).
///
/// Account order: `[delegation_auth (readonly signer), envelope (writable), padding (readonly)]`
///
/// `delegation_auth` must match `envelope.delegation_authority`. `padding` fills
/// the third account slot and is not checked as a signer.
pub struct UpdateAuxiliaryDelegated<'a> {
    pub envelope: &'a AccountView,
    pub delegation_auth: &'a AccountView,
    pub padding: &'a AccountView,
    pub program: &'a AccountView,
    pub sequence: u64,
    pub data: &'a [u8; AUX_DATA_SIZE],
}

impl UpdateAuxiliaryDelegated<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let ix_enum = SlowPathInstruction::UpdateAuxiliaryDelegated {
            sequence: self.sequence,
            data: *self.data,
        };
        let mut buf = [0u8; UPDATE_AUX_SERIALIZED_SIZE];
        wincode::serialize_into(&mut &mut buf[..], &ix_enum)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.delegation_auth.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly(self.padding.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf,
        };
        invoke_signed(
            &ix,
            &[self.delegation_auth, self.envelope, self.padding],
            signers,
        )
    }
}

/// CPI: UpdateAuxiliaryForce (authority overrides both sequence counters).
///
/// Account order: `[authority (readonly signer), envelope (writable), delegation_auth (readonly signer)]`
pub struct UpdateAuxiliaryForce<'a> {
    pub authority: &'a AccountView,
    pub envelope: &'a AccountView,
    pub delegation_auth: &'a AccountView,
    pub program: &'a AccountView,
    pub authority_sequence: u64,
    pub program_sequence: u64,
    pub data: &'a [u8; AUX_DATA_SIZE],
}

impl UpdateAuxiliaryForce<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let ix_enum = SlowPathInstruction::UpdateAuxiliaryForce {
            authority_sequence: self.authority_sequence,
            program_sequence: self.program_sequence,
            data: *self.data,
        };
        let mut buf = [0u8; UPDATE_AUX_FORCE_SERIALIZED_SIZE];
        wincode::serialize_into(&mut &mut buf[..], &ix_enum)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.authority.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly_signer(self.delegation_auth.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf,
        };
        invoke_signed(
            &ix,
            &[self.authority, self.envelope, self.delegation_auth],
            signers,
        )
    }
}
