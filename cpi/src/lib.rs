#![no_std]
//! CPI helpers for invoking the c_u_soon oracle program from another Solana program.
//!
//! Each struct assembles instruction data and accounts, then provides
//! `invoke()` and `invoke_signed()` methods following the pinocchio convention.

extern crate alloc;

use c_u_soon::ORACLE_BYTES;
use c_u_soon_instruction::{
    SlowPathInstruction, WriteSpec, UPDATE_AUX_DELEGATED_RANGE_TAG, UPDATE_AUX_DELEGATED_TAG,
    UPDATE_AUX_FORCE_MAX_SIZE, UPDATE_AUX_FORCE_TAG, UPDATE_AUX_MAX_SIZE,
    UPDATE_AUX_RANGE_MAX_SIZE, UPDATE_AUX_RANGE_TAG, UPDATE_AUX_TAG,
};
use pinocchio::{
    cpi::{invoke_signed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

/// Increment a sequence counter, returning `ArithmeticOverflow` on overflow.
pub fn next_sequence(current: u64) -> Result<u64, ProgramError> {
    current
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)
}

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
/// Wire format: `[disc:4][metadata:8][sequence:8][data:N]`
///
/// Account order: `[authority (readonly signer), envelope (writable), pda (readonly signer)]`
///
/// `pda` is the caller's PDA; the Solana runtime verifies it as a signer to confirm
/// the call's origin.
pub struct UpdateAuxiliary<'a> {
    pub authority: &'a AccountView,
    pub envelope: &'a AccountView,
    pub pda: &'a AccountView,
    pub program: &'a AccountView,
    pub metadata: u64,
    pub sequence: u64,
    pub data: &'a [u8],
}

impl UpdateAuxiliary<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let data_len = self.data.len();
        let total = 20 + data_len;
        if total > UPDATE_AUX_MAX_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut buf = [0u8; UPDATE_AUX_MAX_SIZE];
        buf[..4].copy_from_slice(&UPDATE_AUX_TAG.to_le_bytes());
        buf[4..12].copy_from_slice(&self.metadata.to_le_bytes());
        buf[12..20].copy_from_slice(&self.sequence.to_le_bytes());
        buf[20..20 + data_len].copy_from_slice(self.data);

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.authority.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly_signer(self.pda.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf[..total],
        };
        invoke_signed(&ix, &[self.authority, self.envelope, self.pda], signers)
    }
}

/// CPI: UpdateAuxiliaryDelegated (delegated program writes aux data).
///
/// Wire format: `[disc:4][metadata:8][sequence:8][data:N]`
///
/// Account order: `[delegation_auth (readonly signer), envelope (writable), padding (readonly)]`
///
/// `delegation_auth` must match `envelope.delegation_authority`.
/// `padding` is required so the instruction has 3 accounts and routes to the slow path
/// (2-account instructions are intercepted by the fast path for oracle updates).
pub struct UpdateAuxiliaryDelegated<'a> {
    pub envelope: &'a AccountView,
    pub delegation_auth: &'a AccountView,
    pub padding: &'a AccountView,
    pub program: &'a AccountView,
    pub metadata: u64,
    pub sequence: u64,
    pub data: &'a [u8],
}

impl UpdateAuxiliaryDelegated<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let data_len = self.data.len();
        let total = 20 + data_len;
        if total > UPDATE_AUX_MAX_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut buf = [0u8; UPDATE_AUX_MAX_SIZE];
        buf[..4].copy_from_slice(&UPDATE_AUX_DELEGATED_TAG.to_le_bytes());
        buf[4..12].copy_from_slice(&self.metadata.to_le_bytes());
        buf[12..20].copy_from_slice(&self.sequence.to_le_bytes());
        buf[20..20 + data_len].copy_from_slice(self.data);

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.delegation_auth.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly(self.padding.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf[..total],
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
/// Wire format: `[disc:4][metadata:8][auth_seq:8][prog_seq:8][data:N]`
///
/// Account order: `[authority (readonly signer), envelope (writable), delegation_auth (readonly signer)]`
pub struct UpdateAuxiliaryForce<'a> {
    pub authority: &'a AccountView,
    pub envelope: &'a AccountView,
    pub delegation_auth: &'a AccountView,
    pub program: &'a AccountView,
    pub metadata: u64,
    pub authority_sequence: u64,
    pub program_sequence: u64,
    pub data: &'a [u8],
}

impl UpdateAuxiliaryForce<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let data_len = self.data.len();
        let total = 28 + data_len;
        if total > UPDATE_AUX_FORCE_MAX_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut buf = [0u8; UPDATE_AUX_FORCE_MAX_SIZE];
        buf[..4].copy_from_slice(&UPDATE_AUX_FORCE_TAG.to_le_bytes());
        buf[4..12].copy_from_slice(&self.metadata.to_le_bytes());
        buf[12..20].copy_from_slice(&self.authority_sequence.to_le_bytes());
        buf[20..28].copy_from_slice(&self.program_sequence.to_le_bytes());
        buf[28..28 + data_len].copy_from_slice(self.data);

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.authority.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly_signer(self.delegation_auth.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf[..total],
        };
        invoke_signed(
            &ix,
            &[self.authority, self.envelope, self.delegation_auth],
            signers,
        )
    }
}

/// CPI: UpdateAuxiliaryRange (authority writes a byte range of aux data).
///
/// Wire format: `[disc:4][metadata:8][sequence:8][offset:1][data:N]`
///
/// Account order: `[authority (readonly signer), envelope (writable), pda (readonly signer)]`
pub struct UpdateAuxiliaryRange<'a> {
    pub authority: &'a AccountView,
    pub envelope: &'a AccountView,
    pub pda: &'a AccountView,
    pub program: &'a AccountView,
    pub metadata: u64,
    pub sequence: u64,
    pub offset: u8,
    pub data: &'a [u8],
}

impl UpdateAuxiliaryRange<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let data_len = self.data.len();
        let total = 21 + data_len;
        if total > UPDATE_AUX_RANGE_MAX_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut buf = [0u8; UPDATE_AUX_RANGE_MAX_SIZE];
        buf[..4].copy_from_slice(&UPDATE_AUX_RANGE_TAG.to_le_bytes());
        buf[4..12].copy_from_slice(&self.metadata.to_le_bytes());
        buf[12..20].copy_from_slice(&self.sequence.to_le_bytes());
        buf[20] = self.offset;
        buf[21..21 + data_len].copy_from_slice(self.data);

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.authority.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly_signer(self.pda.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf[..total],
        };
        invoke_signed(&ix, &[self.authority, self.envelope, self.pda], signers)
    }
}

/// CPI: UpdateAuxiliaryDelegatedRange (delegated program writes a byte range of aux data).
///
/// Wire format: `[disc:4][metadata:8][sequence:8][offset:1][data:N]`
///
/// Account order: `[delegation_auth (readonly signer), envelope (writable), padding (readonly)]`
pub struct UpdateAuxiliaryDelegatedRange<'a> {
    pub envelope: &'a AccountView,
    pub delegation_auth: &'a AccountView,
    pub padding: &'a AccountView,
    pub program: &'a AccountView,
    pub metadata: u64,
    pub sequence: u64,
    pub offset: u8,
    pub data: &'a [u8],
}

impl UpdateAuxiliaryDelegatedRange<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let data_len = self.data.len();
        let total = 21 + data_len;
        if total > UPDATE_AUX_RANGE_MAX_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut buf = [0u8; UPDATE_AUX_RANGE_MAX_SIZE];
        buf[..4].copy_from_slice(&UPDATE_AUX_DELEGATED_RANGE_TAG.to_le_bytes());
        buf[4..12].copy_from_slice(&self.metadata.to_le_bytes());
        buf[12..20].copy_from_slice(&self.sequence.to_le_bytes());
        buf[20] = self.offset;
        buf[21..21 + data_len].copy_from_slice(self.data);

        let cpi_accounts = [
            InstructionAccount::readonly_signer(self.delegation_auth.address()),
            InstructionAccount::writable(self.envelope.address()),
            InstructionAccount::readonly(self.padding.address()),
        ];
        let ix = InstructionView {
            program_id: self.program.address(),
            accounts: &cpi_accounts,
            data: &buf[..total],
        };
        invoke_signed(
            &ix,
            &[self.delegation_auth, self.envelope, self.padding],
            signers,
        )
    }
}

/// CPI: UpdateAuxiliaryMultiRange (authority writes multiple byte ranges of aux data).
///
/// Serialized via wincode as `SlowPathInstruction::UpdateAuxiliaryMultiRange`.
///
/// Account order: `[authority (readonly signer), envelope (writable), pda (readonly signer)]`
pub struct UpdateAuxiliaryMultiRange<'a> {
    pub authority: &'a AccountView,
    pub envelope: &'a AccountView,
    pub pda: &'a AccountView,
    pub program: &'a AccountView,
    pub metadata: u64,
    pub sequence: u64,
    pub ranges: &'a [WriteSpec],
}

impl UpdateAuxiliaryMultiRange<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let ix_data = SlowPathInstruction::UpdateAuxiliaryMultiRange {
            metadata: self.metadata,
            sequence: self.sequence,
            ranges: self.ranges.to_vec(),
        };
        let buf = wincode::serialize(&ix_data).map_err(|_| ProgramError::InvalidInstructionData)?;

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

/// CPI: UpdateAuxiliaryDelegatedMultiRange (delegated program writes multiple byte ranges).
///
/// Serialized via wincode as `SlowPathInstruction::UpdateAuxiliaryDelegatedMultiRange`.
///
/// Account order: `[delegation_auth (readonly signer), envelope (writable), padding (readonly)]`
pub struct UpdateAuxiliaryDelegatedMultiRange<'a> {
    pub envelope: &'a AccountView,
    pub delegation_auth: &'a AccountView,
    pub padding: &'a AccountView,
    pub program: &'a AccountView,
    pub metadata: u64,
    pub sequence: u64,
    pub ranges: &'a [WriteSpec],
}

impl UpdateAuxiliaryDelegatedMultiRange<'_> {
    pub fn invoke(&self) -> ProgramResult {
        self.invoke_signed(&[])
    }

    pub fn invoke_signed(&self, signers: &[Signer]) -> ProgramResult {
        let ix_data = SlowPathInstruction::UpdateAuxiliaryDelegatedMultiRange {
            metadata: self.metadata,
            sequence: self.sequence,
            ranges: self.ranges.to_vec(),
        };
        let buf = wincode::serialize(&ix_data).map_err(|_| ProgramError::InvalidInstructionData)?;

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
