//! Off-chain validation utilities for [`CuLaterMask`] permission checks.
//!
//! [`validate_program_change`] and [`validate_authority_change`] verify that a proposed
//! auxiliary data update stays within mask-defined write permissions. [`diff_report`]
//! produces a per-byte breakdown for debugging rejected changes.
//!
//! This module requires the `alloc` feature (gated in `c_u_later/src/lib.rs`).
//! On-chain enforcement uses the bitmask directly in the program handler.

extern crate alloc;

use crate::{BitVec256, CuLaterMask, AUX_SIZE};
use alloc::vec::Vec;

/// Returns `true` if every changed byte is permitted by `mask`.
///
/// A byte at index `i` may differ only if `mask.get_bit(i)` is `true`. Unchanged bytes
/// are always allowed. Returns `false` if `old` and `new` have different lengths.
#[inline]
pub(crate) fn validate_change(old: &[u8], new: &[u8], mask: &BitVec256) -> bool {
    if old.len() != new.len() {
        return false;
    }
    for i in 0..old.len().min(AUX_SIZE) {
        if old[i] != new[i] && !mask.get_bit(i) {
            return false;
        }
    }
    true
}

/// Validate that a change respects the program write mask for type T.
#[inline]
pub fn validate_program_change<T: CuLaterMask>(old: &[u8], new: &[u8]) -> bool {
    let mask = crate::to_program_bitvec::<T>();
    validate_change(old, new, &mask)
}

/// Validate that a change respects the authority write mask for type T.
#[inline]
pub fn validate_authority_change<T: CuLaterMask>(old: &[u8], new: &[u8]) -> bool {
    let mask = crate::to_authority_bitvec::<T>();
    validate_change(old, new, &mask)
}

/// A single byte that changed between old and new auxiliary data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteChange {
    /// Index within the aux buffer (0..AUX_SIZE).
    pub byte_offset: usize,
    /// Value before the change.
    pub old_value: u8,
    /// Value after the change.
    pub new_value: u8,
    /// `true` if the program mask permits writing this byte.
    pub program_allowed: bool,
    /// `true` if the authority mask permits writing this byte.
    pub authority_allowed: bool,
}

/// Summary of all byte-level changes and their permission status.
#[derive(Debug, Clone)]
pub struct ChangeReport {
    /// Each byte that differs between old and new data.
    pub changes: Vec<ByteChange>,
    /// `true` if every changed byte is within the program write mask.
    pub all_program_changes_valid: bool,
    /// `true` if every changed byte is within the authority write mask.
    pub all_authority_changes_valid: bool,
}

/// Produces a per-byte change report for debugging mask validation failures.
///
/// Only bytes where `old[i] != new[i]` appear in [`ChangeReport::changes`]. Each entry
/// records whether the change is permitted by the program and authority masks.
pub fn diff_report<T: CuLaterMask>(old: &[u8], new: &[u8]) -> ChangeReport {
    let program_mask = crate::to_program_bitvec::<T>();
    let authority_mask = crate::to_authority_bitvec::<T>();

    let mut changes = Vec::new();
    for i in 0..old.len().min(new.len()).min(AUX_SIZE) {
        if old[i] != new[i] {
            changes.push(ByteChange {
                byte_offset: i,
                old_value: old[i],
                new_value: new[i],
                program_allowed: program_mask.get_bit(i),
                authority_allowed: authority_mask.get_bit(i),
            });
        }
    }

    let all_program_changes_valid = changes.iter().all(|c| c.program_allowed);
    let all_authority_changes_valid = changes.iter().all(|c| c.authority_allowed);

    ChangeReport {
        changes,
        all_program_changes_valid,
        all_authority_changes_valid,
    }
}

/// Get a bitmask of constant (read-only) fields for type T.
///
/// A byte is marked as constant if neither the program nor the authority
/// is allowed to write to it.
pub(crate) fn constant_mask<T: CuLaterMask>() -> BitVec256 {
    let program_mask = crate::to_program_bitvec::<T>();
    let authority_mask = crate::to_authority_bitvec::<T>();

    let mut result = BitVec256::ZERO;
    for i in 0..256 {
        if !program_mask.get_bit(i) && !authority_mask.get_bit(i) {
            result.set_bit(i);
        }
    }
    result
}

/// Verify that all constant fields remain unchanged between old and new data.
#[inline]
pub fn verify_constants_unchanged<T: CuLaterMask>(old: &[u8], new: &[u8]) -> bool {
    let const_mask = constant_mask::<T>();
    (0..old.len().min(new.len()).min(AUX_SIZE)).all(|i| !const_mask.get_bit(i) || old[i] == new[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_change_simple() {
        let old = [0u8; 256];
        let mut new = [0u8; 256];
        new[0] = 1;

        let mut mask = BitVec256::ZERO;
        mask.set_bit(0);

        assert!(validate_change(&old, &new, &mask));

        let no_mask = BitVec256::ZERO;
        assert!(!validate_change(&old, &new, &no_mask));
    }

    #[test]
    fn test_validate_change_no_changes() {
        let old = [42u8; 256];
        let new = [42u8; 256];
        let no_mask = BitVec256::ZERO;

        assert!(validate_change(&old, &new, &no_mask));
    }

    #[test]
    fn test_validate_change_mismatched_lengths() {
        let old = [0u8; 256];
        let new = [0u8; 100];
        let full_mask = BitVec256::FULL;

        assert!(!validate_change(&old, &new, &full_mask));
    }

    #[test]
    fn test_validate_program_change() {
        let old = [0u8; 256];
        let mut new = [0u8; 256];
        new[0] = 1;

        assert!(validate_program_change::<u8>(&old, &new));

        let mut new2 = [0u8; 256];
        new2[1] = 1;
        assert!(!validate_program_change::<u8>(&old, &new2));
    }

    #[test]
    fn test_diff_report_no_changes() {
        let data = [0u8; 256];
        let report = diff_report::<u8>(&data, &data);
        assert!(report.changes.is_empty());
        assert!(report.all_program_changes_valid);
        assert!(report.all_authority_changes_valid);
    }

    #[test]
    fn test_diff_report_single_change() {
        let old = [0u8; 256];
        let mut new = [0u8; 256];
        new[5] = 42;

        // u64 covers bytes 0-7, so byte 5 is allowed
        let report = diff_report::<u64>(&old, &new);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].byte_offset, 5);
        assert_eq!(report.changes[0].old_value, 0);
        assert_eq!(report.changes[0].new_value, 42);
        assert!(report.changes[0].program_allowed);
        assert!(report.all_program_changes_valid);
    }

    #[test]
    fn test_constant_mask() {
        // u8 is writable by both program and authority in byte 0
        let const_mask = constant_mask::<u8>();
        assert!(!const_mask.get_bit(0));
        assert!(const_mask.get_bit(1));
        assert!(const_mask.get_bit(255));
    }

    #[test]
    fn test_verify_constants_unchanged() {
        let mut old = [0u8; 256];
        let mut new = [0u8; 256];
        old[0] = 1;
        new[0] = 2;

        // u8 is only 1 byte, so bytes 1+ are constant
        assert!(verify_constants_unchanged::<u8>(&old, &new));

        // u16 is 2 bytes, so bytes 2+ are constant
        assert!(verify_constants_unchanged::<u16>(&old, &new));

        // Changing a constant byte should fail
        old[2] = 5;
        new[2] = 6;
        assert!(!verify_constants_unchanged::<u8>(&old, &new));
    }
}
