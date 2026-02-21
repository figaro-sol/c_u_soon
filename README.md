# c_u_soon

Low-CU state updates with validated CPI for associated metadata. Bolts onto existing Solana programs without reworking their data structures.

## Why

Programs that publish data frequently (prices, rates, pool state) pay the full CU cost of their program on every update. You may not want to optimize the main program for this -- it complicates production code, it risks backwards compatibility with existing account layouts, or the accounts just don't have room. And CU optimization at this level is specialized work.

c_u_soon is a separate program that owns a dedicated account (the "envelope") for frequently-updated state. The authority updates it through c_u_soon's fast path instead of routing through the main program.

When the main program processes an event, it often needs to update metadata associated with that state. You could use a separate account for this, but every additional account increases transaction size. Each envelope includes 256 bytes of slow data that the main program can write via CPI, with access control between the envelope owner and the associated program. Frequently-updated data and its metadata share one account.

## How it works

Each envelope PDA has two data regions. The fast data (up to 239 bytes) is updated through the fast path -- fast updates + permissioned CPI metadata in the same account. The slow data (256 bytes) is updated through the slow path, with permission masks controlling access between the envelope owner and a delegated program.

## Fast path

A fast path update costs ~39 CUs. It takes 2 accounts (authority signer + envelope writable), validates the authority, checks the type tag, confirms the sequence is strictly increasing, and copies the payload with a single `sol_memcpy`. No instruction deserialization, no allocations.

Max payload is 239 bytes. Instruction data format: `[oracle_metadata: u64 LE][sequence: u64 LE][payload...]`

Most users interact through the typed interface, which handles the metadata and serialization:

```rust
use c_u_soon_client::fast_path_update_typed;

let price = PriceData { price: 150_000_000, confidence: 50, _pad: [0; 4] };
let ix_data = fast_path_update_typed::<PriceData>(next_sequence, &price);
// accounts: [authority (signer), envelope (writable)]
```

## Workspace

```
sdk/              c_u_soon              core types (Envelope, Mask, TypeHash), no_std
client/           c_u_soon_client       off-chain instruction builders
instruction/      c_u_soon_instruction    shared instruction types
cpi/              c_u_soon_cpi          on-chain CPI builders (FastPathUpdate, UpdateAuxiliary*, next_sequence)
program/          c_u_soon_program      on-chain program (pinocchio)
c_u_later/        c_u_later             compile-time permission masks for slow data
c_u_later/derive/                       proc macro for CuLater
c_u_soon_derive/                        proc macro for TypeHash
```

## Quick start

Enable the `derive` feature for `#[derive(TypeHash)]`:

```toml
c_u_soon = { version = "...", features = ["derive"] }
```

Define your data type with `#[derive(TypeHash)]` and `#[repr(C)]`:

```rust
use bytemuck::{Pod, Zeroable};
use c_u_soon::TypeHash;

#[derive(Clone, Copy, Pod, Zeroable, TypeHash)]
#[repr(C)]
struct PriceData {
    price: u64,
    confidence: u32,
    _pad: [u8; 4],
}
```

Create an envelope:

```rust
use c_u_soon_client::create_envelope_typed;

let seeds: &[&[u8]] = &[b"price", b"SOL"];
let create_data = create_envelope_typed::<PriceData>(seeds, bump);
// accounts: [authority (signer, writable), envelope (writable), system_program]
```

Read data back:

```rust
let envelope: &Envelope = bytemuck::from_bytes(&account_data);
if let Some(price) = envelope.oracle::<PriceData>() {
    // price.price, price.confidence
}
```

## Type safety

Both the fast and slow data slots carry a `StructMetadata` tag: 8 bits of type size, 56-bit FNV-1a hash of the type structure. Read data with the wrong type and you get `None`. The fast path rejects updates where the tag doesn't match, so you can't accidentally interpret `[u8; 12]` bytes as a `PriceData`.

`TypeHash` is implemented for all numeric primitives, fixed-size arrays, and any `#[repr(C)]` struct via derive macro.

## Delegation and slow data

Envelopes support delegation: you register a program as the `delegation_authority`, and it can read/write the 256-byte slow data section via CPI. Two 256-byte masks control which bytes each party can write. `program_bitmask` restricts the delegated program, `user_bitmask` restricts the authority.

### c_u_later

The `c_u_later` crate generates these masks from struct definitions:

```rust
use c_u_later::CuLater;
use bytemuck::{Pod, Zeroable};
use c_u_soon::TypeHash;

#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater)]
#[repr(C)]
struct AmmState {
    #[program]
    pool_price: u64,      // only the delegated program can write this
    #[authority]
    fee_rate: u32,        // only the authority can write this
    #[program]
    #[authority]
    shared_flag: u8,      // both can write
    _reserved: [u8; 3],   // neither can write
}
```

Convert to on-chain mask format:

```rust
use c_u_later::{to_program_wire_mask, to_authority_wire_mask};

let program_mask = to_program_wire_mask::<AmmState>();
let user_mask = to_authority_wire_mask::<AmmState>();
```

For opaque blob fields that don't implement `CuLater`, use `#[embed]`:

```rust
#[derive(Clone, Copy, Pod, Zeroable, TypeHash, CuLater)]
#[repr(C)]
struct WithBlob {
    #[program]
    #[embed]
    opaque: [u8; 32],  // writable as a whole unit, no sub-field decomposition
}
```

`CuLater` also generates role-specific wrappers to avoid cross-role writes in your own code:

```rust
let mut aux = AmmState {
    pool_price: 0,
    fee_rate: 0,
    shared_flag: 0,
    _reserved: [0; 3],
};

{
    let mut p = AmmStateProgram::from_mut(&mut aux);
    *p.pool_price_mut() = 123;
    *p.shared_flag_mut() = 1;
    // p.fee_rate_mut() does not exist
}

{
    let mut a = AmmStateAuthority::from_mut(&mut aux);
    *a.fee_rate_mut() = 5;
    *a.shared_flag_mut() = 2;
    // a.pool_price_mut() does not exist
}
```

Before building a slow-path update, you can validate diffs off-chain:

```rust
use c_u_later::validation::{
    diff_report, validate_authority_change, validate_program_change, verify_constants_unchanged,
};

let old_bytes = bytemuck::bytes_of(&old_aux);
let new_bytes = bytemuck::bytes_of(&new_aux);

assert!(validate_program_change::<AmmState>(old_bytes, new_bytes));
assert!(verify_constants_unchanged::<AmmState>(old_bytes, new_bytes));
let report = diff_report::<AmmState>(old_bytes, new_bytes);
```

## CPI from your program

`c_u_soon_cpi` now uses struct-based CPI builders with `invoke()` / `invoke_signed()`.
Use `next_sequence(current)` to safely increment counters (`ArithmeticOverflow` on overflow).

Update slow data as the authority:

```rust
use c_u_soon::TypeHash;
use c_u_soon_cpi::{next_sequence, UpdateAuxiliary};

let next = next_sequence(current_authority_aux_sequence)?;
UpdateAuxiliary {
    authority,
    envelope,
    pda, // caller PDA signer
    program: c_u_soon_program,
    metadata: AmmState::METADATA.as_u64(),
    sequence: next,
    data: bytemuck::bytes_of(&new_aux),
}
.invoke_signed(signers)?;
```

Update slow data as the delegated program:

```rust
use c_u_soon::TypeHash;
use c_u_soon_cpi::{next_sequence, UpdateAuxiliaryDelegated};

let next = next_sequence(current_program_aux_sequence)?;
UpdateAuxiliaryDelegated {
    delegation_auth,
    envelope,
    padding, // required third account for slow-path dispatch
    program: c_u_soon_program,
    metadata: AmmState::METADATA.as_u64(),
    sequence: next,
    data: bytemuck::bytes_of(&new_aux),
}
.invoke_signed(signers)?;
```

Force update (both parties sign, no bitmask restriction):

```rust
use c_u_soon::TypeHash;
use c_u_soon_cpi::{next_sequence, UpdateAuxiliaryForce};

UpdateAuxiliaryForce {
    authority,
    envelope,
    delegation_auth,
    program: c_u_soon_program,
    metadata: AmmState::METADATA.as_u64(),
    authority_sequence: next_sequence(current_authority_aux_sequence)?,
    program_sequence: next_sequence(current_program_aux_sequence)?,
    data: bytemuck::bytes_of(&new_aux),
}
.invoke_signed(signers)?;
```

Fast path via CPI:

```rust
use c_u_soon::TypeHash;
use c_u_soon_cpi::{next_sequence, FastPathUpdate};

FastPathUpdate {
    authority,
    envelope,
    program: c_u_soon_program,
    oracle_meta: PriceData::METADATA.as_u64(),
    sequence: next_sequence(current_oracle_sequence)?,
    payload: bytemuck::bytes_of(&new_price),
}
.invoke_signed(signers)?;
```

Migration note: older `invoke_fast_path` / `invoke_update_*` helper functions were removed.
The new format for slow updates is explicit manual wire data:
`[disc:4][metadata:8][sequence(s):8/16][data:N]`.

## Slow path instructions

**Create**: initialize envelope PDA

| Account        | Constraints             |
|----------------|-------------------------|
| authority      | signer, writable        |
| envelope       | writable                |
| system_program |                         |

**Close**: destroy envelope, drain lamports

| Account   | Constraints        |
|-----------|--------------------|
| authority | signer             |
| envelope  | writable, owned    |
| recipient | writable           |

**SetDelegatedProgram**: enable delegation with bitmasks

| Account              | Constraints     |
|----------------------|-----------------|
| authority            | signer          |
| envelope             | writable, owned |
| delegation_authority | signer          |

**ClearDelegation**: remove delegation (wipes fast + slow data)

| Account              | Constraints     |
|----------------------|-----------------|
| authority            | signer          |
| envelope             | writable, owned |
| delegation_authority | signer          |

**UpdateAuxiliary**: authority writes slow data. Requires active delegation. Writes restricted by user_bitmask.

| Account     | Constraints     |
|-------------|-----------------|
| authority   | signer          |
| envelope    | writable, owned |
| pda         | signer          |

**UpdateAuxiliaryDelegated**: delegated program writes slow data. Requires active delegation. Writes restricted by program_bitmask. Sequence must be strictly greater than program_aux_sequence.

| Account              | Constraints     |
|----------------------|-----------------|
| delegation_authority | signer          |
| envelope             | writable, owned |
| (padding)            |                 |

**UpdateAuxiliaryForce**: both parties sign, no bitmask restriction. Requires active delegation. Both authority_sequence and program_sequence must be strictly greater than their stored values.

| Account              | Constraints     |
|----------------------|-----------------|
| authority            | signer          |
| envelope             | writable, owned |
| delegation_authority | signer          |

## Building

Requires the Solana BPF toolchain (`cargo build-sbf`).

```bash
# Build the program
make build-sbf

# Run all tests (builds BPF artifacts first)
make test

# SDK and client tests only (no BPF build needed)
make test-sdk

# Delegation + CPI security tests
make test-security

# CPI integration tests (LiteSVM)
make test-cpi
```

## Testing

Mollusk SVM handles single-program unit tests (create, update, close, delegation, security edge cases) without a validator. Separate delegation security tests focus on bitmask enforcement and authorization boundaries. LiteSVM runs multi-program CPI tests against two test programs: `byte_writer` (legitimate caller) and `attacker_probe` (various attack vectors).

## Dependencies

[pinocchio](https://github.com/febo/pinocchio) for the on-chain program framework, [bytemuck](https://crates.io/crates/bytemuck) for zero-copy types, [wincode](https://crates.io/crates/wincode) for instruction serialization, [solana-address](https://crates.io/crates/solana-address) for address types.

## License

Apache-2.0
