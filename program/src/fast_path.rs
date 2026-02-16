use c_u_soon::Envelope;
use pinocchio::{
    address::address_eq,
    entrypoint::{lazy::InstructionContext, AssumeLikeType, AssumeNeverDup, CheckLikeType},
    error::ProgramError,
};

use crate::slow_path;

#[cold]
#[inline(never)]
fn hard_exit(_msg: &str, _for_error: ProgramError) -> ! {
    #[cfg(target_os = "solana")]
    {
        // we don't have enough CUs for sol log!

        use core::arch::asm;
        let e: u64 = _for_error.into();
        unsafe {
            asm!(
                "mov64 r0, {0}",
                "exit",
                in(reg) e,
                options(noreturn)
            );
        }
    }
    #[cfg(not(target_os = "solana"))]
    {
        panic!("{}", _msg);
    }
}

const INPUT_BASE: u64 = 0x400000000;

#[inline]
unsafe fn sol_memcpy(_dst: *mut u8, _src: *const u8, _n: u64) -> ! {
    #[cfg(target_os = "solana")]
    {
        // why can we do this? void syscalls set r0 to 0 which is what we already want to return
        unsafe {
            core::arch::asm!(
                "call sol_memcpy_",
                "exit",
                in("r1") _dst,
                in("r2") _src,
                in("r3") _n,
                options(noreturn),
            );
        }
    }
    #[cfg(not(target_os = "solana"))]
    {
        unreachable!("sol_memcpy should only be called in the Solana environment");
    }
}

// This is probably better written as asm
// but having mostly plain rust makes the development far easier
// we could save 1 CU on never using r0 and on happy path
pub(super) unsafe fn fast_path(input: *mut u8) -> u64 {
    let num_accounts = *(input as *const u64);

    if num_accounts != 2 {
        return slow_path::slow_entrypoint(input);
    }

    let mut ctx = InstructionContext::new_unchecked(input);

    let Ok(authority_account) =
        ctx.next_account_guarded(&AssumeNeverDup::new(), &CheckLikeType::<()>::new())
    else {
        hard_exit(
            "First account does not have size of 0",
            ProgramError::InvalidAccountData,
        )
    };

    if !authority_account.is_signer() {
        hard_exit(
            "Authority account must be signer",
            ProgramError::MissingRequiredSignature,
        )
    }

    // if length is too long or too short, no good. BUT!
    // a. we know there are no other accounts in the program. only the authority and this weird non-envelope account
    // b. we know the account is not an envelope account
    // c. somebody could transfer an account to the program and then use this problem to write to it.
    // c. 1. HOWEVER. that's not a legitimate c_u_soon account and would not pass a PDA check.
    // d. Conclusion:
    // d. 1. wrong size in second account does NOT allow one to write to an oracle that is not theirs, or in fact, an oracle at all.
    // d. 2. this is inherent since if the second account is the wrong size it implies it's not an oracle account in the first place

    let Ok(oracle_account) =
        ctx.next_account_guarded(&AssumeNeverDup::new(), &AssumeLikeType::<Envelope>::new())
    else {
        hard_exit(
            "Second account does not have size of Envelope",
            ProgramError::InvalidAccountData,
        )
    };

    let oracle_data = bytemuck::from_bytes_mut::<Envelope>(oracle_account.borrow_unchecked_mut());

    if !address_eq(&oracle_data.authority, authority_account.address()) {
        hard_exit(
            "Authority account does not match envelope authority",
            ProgramError::IncorrectAuthority,
        )
    }

    // compiler doesn't do our 'only load first byte for inherent safety'
    let raw_instruction_data_header = ctx.cursor();

    // force to only load the first byte.
    // this gives us trivial clamping to prevent reading/writing off of the end
    // this is quite important since if metadata is ever added,
    // this prevents the user from turning this into a full write-past-the-oracle problem

    let data_size = *raw_instruction_data_header as u64;
    let data_ptr = raw_instruction_data_header.add(std::mem::size_of::<u64>());
    let sequence = *(data_ptr as *const u64);

    if sequence <= oracle_data.oracle_state.sequence {
        hard_exit("Sequence stale", ProgramError::InvalidInstructionData);
    }

    // by the u8 construction we can assert that this is true already
    // this only helps remind the compiler

    // trick here where we copy the sequence as part of the memcpy
    // avoids pointer manip as well as the store
    let oracle_state_bytes_mut = bytemuck::bytes_of_mut(&mut oracle_data.oracle_state);

    // informing the compiler that the input has a constant address very sadly does not work
    // it just inserts pointless ops. but computing the known constant offsets and adding to the constant base
    // works perfectly
    let oracle_state_bytes_offset = oracle_state_bytes_mut.as_ptr().offset_from(input);
    let instruction_data_offset = data_ptr.offset_from(input);
    let constant_propagated_oracle_pointer =
        (INPUT_BASE + oracle_state_bytes_offset as u64) as *mut u8;
    let constant_propagated_instruction_pointer =
        (INPUT_BASE + instruction_data_offset as u64) as *const u8;
    // 10CU flat cost. you can add all sorts of shenanigans here to include
    // a few sort of hyper fast path optimizations but it's really not worth it imo
    sol_memcpy(
        constant_propagated_oracle_pointer,
        constant_propagated_instruction_pointer,
        data_size,
    );
}
