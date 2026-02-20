/// Solana program entry point.
///
/// # Safety
///
/// `input` must point to the Solana runtime's serialized account blob for this invocation.
/// The runtime provides a valid pointer; nothing outside the runtime should call this.
///
/// Returns 0 on success or a [`pinocchio::error::ProgramError`] discriminant on failure.
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    super::fast_path::fast_path(input)
}
