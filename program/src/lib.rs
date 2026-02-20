//! Solana on-chain program for the c_u_soon oracle.
//!
//! The entry point dispatches on account count: two accounts take the fast path
//! (direct oracle data update), anything else goes to the slow path (account
//! administration via [`SlowPathInstruction`]).
//!
//! Requires `asm_experimental_arch` for sBPF inline assembly in the fast path.
//!
//! [`SlowPathInstruction`]: c_u_soon_instruction::SlowPathInstruction
#![allow(unexpected_cfgs)]
#![feature(asm_experimental_arch)]

mod entrypoint;
mod fast_path;
mod instructions;
mod pda;
mod slow_path;
