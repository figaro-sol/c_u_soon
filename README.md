# c_u_soon

A Solana program for type-safe oracle state, optimized to make frequent data updates as cheap as possible.

The idea: your program probably has some data that changes constantly (prices, rates, positions) and other data that changes rarely. Instead of paying full CU cost on every update by routing through your program, you park the hot data in a c_u_soon envelope and update it directly via the fast path. Your program still controls associated state through CPI and the delegation system, so you're not giving anything up. You're just not paying for your whole program's deserialization on every price tick.

## How it works

Each piece of hot data lives in an Envelope, an 864-byte PDA. It holds 256 bytes of type-tagged, sequenced oracle state (the fast path target), 256 bytes of auxiliary data with bytewise permission masks, and optional delegation so a host program can still modify associated state via CPI.

Two execution paths:

The fast path takes exactly 2 accounts (authority + envelope). Direct memcpy, minimal branching. Validate the signer, check the type tag, enforce monotonic sequencing, copy the payload. That's it.

Everything else goes through the slow path (3+ accounts): create, close, delegation setup, auxiliary data updates.

## Workspace

```
sdk/            c_u_soon        core types (Envelope, Bitmask, TypeHash), no_std
client/         c_u_soon_client instruction builders
program/        c_u_soon_program on-chain program (pinocchio)
c_u_later/      c_u_later       compile-time permission masks for auxiliary data
c_u_later/derive/               proc macro for CuLater
c_u_soon_derive/                proc macro for TypeHash
```

## Quick start

Define your oracle data type:

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

Create an envelope and push updates:

```rust
use c_u_soon_client::{create_envelope_typed, fast_path_update_typed};

// Create
let seeds: &[&[u8]] = &[b"price", b"SOL"];
let create_data = create_envelope_typed::<PriceData>(seeds, bump);
// accounts: [authority (signer, writable), envelope (writable), system_program]

// Update via fast path
let price = PriceData { price: 150_000_000, confidence: 50, _pad: [0; 4] };
let update_data = fast_path_update_typed::<PriceData>(sequence, &price);
// accounts: [authority (signer), envelope (writable)]
```

Read oracle data from an envelope:

```rust
let envelope: &Envelope = bytemuck::from_bytes(&account_data);
if let Some(price) = envelope.oracle::<PriceData>() {
    println!("price={} conf={}", price.price, price.confidence);
}
```

## Type safety

Every oracle and auxiliary data slot carries a `StructMetadata` tag: 8 bits of type size, 56-bit FNV-1a hash of the type structure. Read data with the wrong type and you get `None`. The fast path rejects updates where the metadata doesn't match, so you can't accidentally interpret `[u8; 12]` bytes as a `PriceData`.

`TypeHash` is implemented for all numeric primitives, fixed-size arrays, and any `#[repr(C)]` struct via derive macro.

## Delegation and auxiliary data

Your host program shouldn't have to give up control just because the hot data lives elsewhere. Envelopes support delegation: you register your program as the `delegation_authority`, and it can read/write the 256-byte auxiliary data section via CPI. Two 128-byte bitmasks control who can write which bytes. `program_bitmask` restricts the delegated program, `user_bitmask` restricts the authority. Each byte in the mask is either `0x00` (writable) or `0xFF` (blocked), nothing in between.

### c_u_later

The `c_u_later` crate generates these bitmasks from struct definitions:

```rust
use c_u_later::CuLater;
use bytemuck::{Pod, Zeroable};

#[derive(Clone, Copy, Pod, Zeroable, CuLater)]
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

Convert to on-chain bitmask format:

```rust
use c_u_later::{to_program_wire_mask, to_authority_wire_mask};

let program_mask = to_program_wire_mask::<AmmState>();
let user_mask = to_authority_wire_mask::<AmmState>();
```

For opaque blob fields that don't implement `CuLater`, use `#[embed]`:

```rust
#[derive(Clone, Copy, Pod, Zeroable, CuLater)]
#[repr(C)]
struct WithBlob {
    #[program]
    #[embed]
    opaque: [u8; 32],  // writable as a whole unit, no sub-field decomposition
}
```

## Instructions

### Fast path (2 accounts)

| Account     | Constraints        |
|-------------|--------------------|
| authority   | signer             |
| envelope    | writable, owned    |

Instruction data: `[oracle_metadata: u64 LE][sequence: u64 LE][payload...]`

Sequence must be strictly greater than the current value.

### Slow path

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

**ClearDelegation**: remove delegation (wipes oracle + auxiliary data)

| Account              | Constraints     |
|----------------------|-----------------|
| authority            | signer          |
| envelope             | writable, owned |
| delegation_authority | signer          |

**UpdateAuxiliary**: authority writes auxiliary data (respects user_bitmask when delegated)

| Account     | Constraints     |
|-------------|-----------------|
| authority   | signer          |
| envelope    | writable, owned |
| pda_account | signer          |

**UpdateAuxiliaryDelegated**: delegated program writes auxiliary data (respects program_bitmask)

| Account              | Constraints     |
|----------------------|-----------------|
| envelope             | writable, owned |
| delegation_authority | signer          |
| (padding)            |                 |

**UpdateAuxiliaryForce**: both parties sign, bypasses bitmask restrictions

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

# Delegation security tests
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
