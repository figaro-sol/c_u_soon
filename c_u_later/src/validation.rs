extern crate alloc;

use crate::{BitVec256, CuLaterMask, AUX_SIZE};
use alloc::vec::Vec;

/// Validate that a change from old to new is permitted by the given mask.
///
/// Returns true if all byte changes are either:
/// 1. Allowed by the mask (mask.get_bit(i) == true), or
/// 2. The byte didn't change (old[i] == new[i])
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

/// Record of a single byte change with permission information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteChange {
    pub byte_offset: usize,
    pub old_value: u8,
    pub new_value: u8,
    pub program_allowed: bool,
    pub authority_allowed: bool,
}

/// Detailed report of all byte changes and validation results.
#[derive(Debug, Clone)]
pub struct ChangeReport {
    pub changes: Vec<ByteChange>,
    pub all_program_changes_valid: bool,
    pub all_authority_changes_valid: bool,
}

/// Generate a detailed change report comparing old and new auxiliary data.
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
