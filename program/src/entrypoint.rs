#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    super::fast_path::fast_path(input)
}
