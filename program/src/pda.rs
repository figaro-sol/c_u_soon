use pinocchio::{error::ProgramError, Address};

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn create_program_address(
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<Address, ProgramError> {
    Address::create_program_address(seeds, program_id).map_err(|_| ProgramError::InvalidSeeds)
}

#[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), test))]
pub fn create_program_address(
    seeds: &[&[u8]],
    program_id: &Address,
) -> Result<Address, ProgramError> {
    use solana_sdk::pubkey::Pubkey as SolanaPubkey;
    let program_pubkey = SolanaPubkey::new_from_array(program_id.to_bytes());
    SolanaPubkey::create_program_address(seeds, &program_pubkey)
        .map(|pk| Address::from(pk.to_bytes()))
        .map_err(|_| ProgramError::InvalidSeeds)
}

#[cfg(all(not(any(target_os = "solana", target_arch = "bpf")), not(test)))]
pub fn create_program_address(
    _seeds: &[&[u8]],
    _program_id: &Address,
) -> Result<Address, ProgramError> {
    unimplemented!("create_program_address only available on BPF or in tests")
}
