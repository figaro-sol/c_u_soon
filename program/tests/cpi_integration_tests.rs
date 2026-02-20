mod common;

use c_u_soon::{Envelope, Mask, AUX_DATA_SIZE};
use c_u_soon_client::{
    set_delegated_program_instruction_data, update_auxiliary_force_instruction_data,
    update_auxiliary_instruction_data,
};
use common::{
    create_delegated_envelope, create_existing_envelope, create_funded_account, LOG_LOCK,
    PROGRAM_ID, PROGRAM_PATH,
};
use mollusk_svm::result::Check;
use mollusk_svm::Mollusk;
use pinocchio::{error::ProgramError, Address};
use solana_sdk::instruction::{AccountMeta, Instruction};

// Program IDs for CPI test programs (arbitrary but stable)
const BYTE_WRITER_ID: Address = Address::new_from_array([
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
]);

const ATTACKER_PROBE_ID: Address = Address::new_from_array([
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
]);

const C_U_SOON_SO_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/deploy/c_u_soon_program.so"
);

const BYTE_WRITER_SO_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-programs/byte_writer/target/deploy/byte_writer.so"
);

const ATTACKER_PROBE_SO_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-programs/attacker_probe/target/deploy/attacker_probe.so"
);

// -- Mollusk Security Integration Tests --
// These tests verify core security properties of c_u_soon using Mollusk (single-program harness)

/// Test that delegated writes with bitmask restrictions are enforced
#[test]
fn test_delegated_bitmask_enforcement() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let pda = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let mut user_bitmask = Mask::ALL_BLOCKED;
    user_bitmask.allow(0); // Allow write to byte 0 only

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_authority,
        Mask::ALL_BLOCKED, // Block all program writes
        user_bitmask,
    );

    let mut data = [0u8; AUX_DATA_SIZE];
    data[0] = 0xAA; // Allowed (byte 0)
    data[1] = 0xBB; // NOT allowed (byte 1)

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_instruction_data(1, data).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(pda, true),
        ],
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (pda, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

/// Test that authorization is required for delegation modifications
#[test]
fn test_delegation_requires_authority() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let imposter = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_existing_envelope(&authority, 0);

    let mut program_bitmask = Mask::ALL_BLOCKED;
    program_bitmask.allow(0);
    let mut user_bitmask = Mask::ALL_BLOCKED;
    user_bitmask.allow(0);

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &set_delegated_program_instruction_data(program_bitmask, user_bitmask).unwrap(),
        vec![
            AccountMeta::new_readonly(imposter, true), // Wrong authority
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
        ],
    );

    mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (imposter, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(0)),
        ],
        &[Check::err(ProgramError::IncorrectAuthority)],
    );
}

/// Test that UpdateAuxiliaryForce correctly bumps both sequences
#[test]
fn test_force_update_increments_sequences() {
    let _log = LOG_LOCK.read().unwrap();
    let mollusk = Mollusk::new(&PROGRAM_ID, PROGRAM_PATH);

    let authority = Address::new_unique();
    let delegation_authority = Address::new_unique();
    let envelope_pubkey = Address::new_unique();

    let envelope = create_delegated_envelope(
        &authority,
        &delegation_authority,
        Mask::ALL_WRITABLE,
        Mask::ALL_WRITABLE,
    );

    let mut data = [0u8; AUX_DATA_SIZE];
    data[0] = 99;

    let instruction = Instruction::new_with_bytes(
        PROGRAM_ID,
        &update_auxiliary_force_instruction_data(5, 3, data).unwrap(),
        vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(envelope_pubkey, false),
            AccountMeta::new_readonly(delegation_authority, true),
        ],
    );

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (authority, create_funded_account(1_000_000_000)),
            (envelope_pubkey, envelope),
            (delegation_authority, create_funded_account(1_000_000_000)),
        ],
        &[Check::success()],
    );

    let env: &Envelope = bytemuck::from_bytes(
        &result.resulting_accounts[1].1.data[..core::mem::size_of::<Envelope>()],
    );
    assert_eq!(env.authority_aux_sequence, 5);
    assert_eq!(env.program_aux_sequence, 3);
    assert_eq!(env.auxiliary_data[0], 99);
}

// -- LiteSVM Multi-Program CPI Tests --
// These tests verify security properties across the CPI boundary using actual SBF programs

#[cfg(test)]
mod litesvm_tests {
    use super::*;
    use bytemuck::bytes_of;
    use c_u_soon::{Envelope, OracleState, StructMetadata, ORACLE_BYTES};
    use litesvm::LiteSVM;
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        signature::Keypair,
        signer::Signer,
        transaction::Transaction,
    };

    fn byte_writer_fast_path_ix_data(oracle_meta: u64, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 8 + 1 + payload.len());
        v.push(0x00); // UpdateViaFastPath
        v.extend_from_slice(&oracle_meta.to_le_bytes());
        v.extend_from_slice(&sequence.to_le_bytes());
        v.push(payload.len() as u8);
        v.extend_from_slice(payload);
        v
    }

    fn attacker_fast_path_without_signer(
        oracle_meta: u64,
        sequence: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 8 + 1 + payload.len());
        v.push(0x00); // FastPathWithoutAuthoritySigner
        v.extend_from_slice(&oracle_meta.to_le_bytes());
        v.extend_from_slice(&sequence.to_le_bytes());
        v.push(payload.len() as u8);
        v.extend_from_slice(payload);
        v
    }

    fn attacker_fast_path_wrong_authority(
        oracle_meta: u64,
        sequence: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 8 + 1 + payload.len());
        v.push(0x01); // FastPathWithWrongAuthority
        v.extend_from_slice(&oracle_meta.to_le_bytes());
        v.extend_from_slice(&sequence.to_le_bytes());
        v.push(payload.len() as u8);
        v.extend_from_slice(payload);
        v
    }

    fn attacker_slow_path_without_pda_signer(sequence: u64, aux_data: &[u8; 256]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 256);
        v.push(0x03); // SlowPathWithoutPdaSigner
        v.extend_from_slice(&sequence.to_le_bytes());
        v.extend_from_slice(aux_data);
        v
    }

    fn attacker_wrong_delegation_authority(sequence: u64, aux_data: &[u8; 256]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 256);
        v.push(0x02); // WrongDelegationAuthority
        v.extend_from_slice(&sequence.to_le_bytes());
        v.extend_from_slice(aux_data);
        v
    }

    fn attacker_stale_sequence(oracle_meta: u64, sequence: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 8 + 1 + payload.len());
        v.push(0x04); // StaleSequence
        v.extend_from_slice(&oracle_meta.to_le_bytes());
        v.extend_from_slice(&sequence.to_le_bytes());
        v.push(payload.len() as u8);
        v.extend_from_slice(payload);
        v
    }

    fn byte_writer_slow_path_ix_data(sequence: u64, aux_data: &[u8; 256]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 256);
        v.push(0x01); // UpdateViaSlowPath
        v.extend_from_slice(&sequence.to_le_bytes());
        v.extend_from_slice(aux_data);
        v
    }

    fn byte_writer_delegated_ix_data(sequence: u64, aux_data: &[u8; 256]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 256);
        v.push(0x02); // UpdateViaDelegated
        v.extend_from_slice(&sequence.to_le_bytes());
        v.extend_from_slice(aux_data);
        v
    }

    fn byte_writer_force_ix_data(auth_seq: u64, prog_seq: u64, aux_data: &[u8; 256]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 8 + 8 + 256);
        v.push(0x03); // UpdateViaForce
        v.extend_from_slice(&auth_seq.to_le_bytes());
        v.extend_from_slice(&prog_seq.to_le_bytes());
        v.extend_from_slice(aux_data);
        v
    }

    fn make_envelope(authority: &Address, seq: u64) -> solana_sdk::account::Account {
        use bytemuck::Zeroable;
        let envelope = Envelope {
            authority: *authority,
            oracle_state: OracleState {
                oracle_metadata: StructMetadata::ZERO,
                sequence: seq,
                data: [0u8; ORACLE_BYTES],
                _pad: [0u8; 1],
            },
            bump: 0,
            _padding: [0u8; 7],
            delegation_authority: Address::zeroed(),
            program_bitmask: Mask::ALL_BLOCKED,
            user_bitmask: Mask::ALL_BLOCKED,
            authority_aux_sequence: 0,
            program_aux_sequence: 0,
            auxiliary_metadata: StructMetadata::ZERO,
            auxiliary_data: [0u8; AUX_DATA_SIZE],
        };
        solana_sdk::account::Account {
            lamports: 1_000_000_000,
            data: bytes_of(&envelope).to_vec(),
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        }
    }

    fn make_delegated_envelope(
        authority: &Address,
        delegation_auth: &Address,
        program_bitmask: Mask,
        user_bitmask: Mask,
    ) -> solana_sdk::account::Account {
        let envelope = Envelope {
            authority: *authority,
            oracle_state: OracleState {
                oracle_metadata: StructMetadata::ZERO,
                sequence: 0,
                data: [0u8; ORACLE_BYTES],
                _pad: [0u8; 1],
            },
            bump: 0,
            _padding: [0u8; 7],
            delegation_authority: *delegation_auth,
            program_bitmask,
            user_bitmask,
            authority_aux_sequence: 0,
            program_aux_sequence: 0,
            auxiliary_metadata: StructMetadata::ZERO,
            auxiliary_data: [0u8; AUX_DATA_SIZE],
        };
        solana_sdk::account::Account {
            lamports: 1_000_000_000,
            data: bytes_of(&envelope).to_vec(),
            owner: PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        }
    }

    fn setup_svm() -> LiteSVM {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(PROGRAM_ID, C_U_SOON_SO_PATH)
            .expect("c_u_soon .so not found; run make build-sbf first");
        svm
    }

    /// CPI via byte_writer to c_u_soon fast path succeeds
    #[test]
    fn test_cpi_fast_path_via_byte_writer_succeeds() {
        let mut svm = setup_svm();
        svm.add_program_from_file(BYTE_WRITER_ID, BYTE_WRITER_SO_PATH)
            .expect("byte_writer .so not found; run make build-sbf-test-programs first");

        let authority_kp = Keypair::new();
        let authority_addr = authority_kp.pubkey();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&authority_addr, 1_000_000_000).unwrap();
        svm.set_account(envelope_addr, make_envelope(&authority_addr, 0))
            .unwrap();

        let ix_data = byte_writer_fast_path_ix_data(0, 1, &[0xAB]);
        let instruction = Instruction::new_with_bytes(
            BYTE_WRITER_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(authority_addr, true), // [0] authority, signer
                AccountMeta::new(envelope_addr, false),          // [1] envelope, writable
                AccountMeta::new_readonly(PROGRAM_ID, false),    // [2] c_u_soon program
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority_addr),
            &[&authority_kp],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(tx);
        assert!(result.is_ok(), "CPI fast path should succeed: {:?}", result);

        let data = svm.get_account(&envelope_addr).unwrap().data;
        let env: &Envelope = bytemuck::from_bytes(&data[..core::mem::size_of::<Envelope>()]);
        assert_eq!(env.oracle_state.sequence, 1);
        assert_eq!(env.oracle_state.data[0], 0xAB);
    }

    /// Attack: CPI with authority NOT marked as signer → c_u_soon rejects
    #[test]
    fn test_cpi_attack_without_authority_signer() {
        let mut svm = setup_svm();
        svm.add_program_from_file(ATTACKER_PROBE_ID, ATTACKER_PROBE_SO_PATH)
            .expect("attacker_probe .so not found; run make build-sbf-test-programs first");

        let authority_kp = Keypair::new();
        let authority_addr = authority_kp.pubkey();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&authority_addr, 1_000_000_000).unwrap();
        svm.set_account(envelope_addr, make_envelope(&authority_addr, 0))
            .unwrap();

        // Attack: attacker_probe will mark authority as NOT signer in CPI metadata
        let ix_data = attacker_fast_path_without_signer(0, 1, &[0xAB]);
        let instruction = Instruction::new_with_bytes(
            ATTACKER_PROBE_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(authority_addr, true), // top-level: IS signer
                AccountMeta::new(envelope_addr, false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority_addr),
            &[&authority_kp],
            svm.latest_blockhash(),
        );

        // c_u_soon sees authority.is_signer() = false → MissingRequiredSignature
        let result = svm.send_transaction(tx);
        assert!(
            result.is_err(),
            "Attack without authority signer should be rejected"
        );
    }

    /// Attack: CPI with wrong authority (not the envelope's authority) → c_u_soon rejects
    #[test]
    fn test_cpi_attack_wrong_authority() {
        let mut svm = setup_svm();
        svm.add_program_from_file(ATTACKER_PROBE_ID, ATTACKER_PROBE_SO_PATH)
            .expect("attacker_probe .so not found; run make build-sbf-test-programs first");

        let actual_authority_kp = Keypair::new();
        let wrong_authority_kp = Keypair::new();
        let wrong_authority_addr = wrong_authority_kp.pubkey();
        let envelope_addr = Address::new_unique();

        // Envelope has actual_authority, but wrong_authority will sign
        svm.airdrop(&wrong_authority_addr, 1_000_000_000).unwrap();
        svm.set_account(
            envelope_addr,
            make_envelope(&actual_authority_kp.pubkey(), 0),
        )
        .unwrap();

        // Attack: pass wrong_authority as signer — it IS a signer but != envelope.authority
        let ix_data = attacker_fast_path_wrong_authority(0, 1, &[0xAB]);
        let instruction = Instruction::new_with_bytes(
            ATTACKER_PROBE_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(wrong_authority_addr, true), // wrong authority, signer
                AccountMeta::new(envelope_addr, false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&wrong_authority_addr),
            &[&wrong_authority_kp],
            svm.latest_blockhash(),
        );

        // c_u_soon sees wrong authority → IncorrectAuthority
        let result = svm.send_transaction(tx);
        assert!(
            result.is_err(),
            "Attack with wrong authority should be rejected"
        );
    }

    /// Attack: UpdateAuxiliary without PDA signer when no delegation → c_u_soon rejects
    #[test]
    fn test_cpi_attack_slow_path_without_pda_signer() {
        let mut svm = setup_svm();
        svm.add_program_from_file(ATTACKER_PROBE_ID, ATTACKER_PROBE_SO_PATH)
            .expect("attacker_probe .so not found; run make build-sbf-test-programs first");

        let authority_kp = Keypair::new();
        let authority_addr = authority_kp.pubkey();
        let fake_pda = Keypair::new();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&authority_addr, 1_000_000_000).unwrap();
        svm.set_account(envelope_addr, make_envelope(&authority_addr, 0))
            .unwrap();
        svm.set_account(fake_pda.pubkey(), create_funded_account(0))
            .unwrap();

        let aux_data = [0u8; 256];
        let ix_data = attacker_slow_path_without_pda_signer(1, &aux_data);
        let instruction = Instruction::new_with_bytes(
            ATTACKER_PROBE_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(authority_addr, true), // [0] authority, signer
                AccountMeta::new(envelope_addr, false),          // [1] envelope, writable
                AccountMeta::new_readonly(fake_pda.pubkey(), false), // [2] pda, NOT signer
                AccountMeta::new_readonly(PROGRAM_ID, false),    // [3] c_u_soon
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority_addr),
            &[&authority_kp],
            svm.latest_blockhash(),
        );

        // c_u_soon sees pda_account.is_signer() = false → MissingRequiredSignature
        let result = svm.send_transaction(tx);
        assert!(
            result.is_err(),
            "Attack without PDA signer should be rejected"
        );
    }

    /// CPI via byte_writer 0x01: UpdateAuxiliary (authority writes slow data, no delegation)
    #[test]
    fn test_cpi_slow_path_via_byte_writer() {
        let mut svm = setup_svm();
        svm.add_program_from_file(BYTE_WRITER_ID, BYTE_WRITER_SO_PATH)
            .expect("byte_writer .so not found");

        let authority_kp = Keypair::new();
        let authority_addr = authority_kp.pubkey();
        let pda_kp = Keypair::new();
        let pda_addr = pda_kp.pubkey();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&authority_addr, 1_000_000_000).unwrap();
        svm.set_account(envelope_addr, make_envelope(&authority_addr, 0))
            .unwrap();
        svm.set_account(pda_addr, create_funded_account(0)).unwrap();

        let mut aux_data = [0u8; 256];
        aux_data[0] = 0xCC;
        aux_data[255] = 0xDD;
        let ix_data = byte_writer_slow_path_ix_data(1, &aux_data);

        let instruction = Instruction::new_with_bytes(
            BYTE_WRITER_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(authority_addr, true),
                AccountMeta::new(envelope_addr, false),
                AccountMeta::new_readonly(pda_addr, true),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority_addr),
            &[&authority_kp, &pda_kp],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(tx);
        assert!(result.is_ok(), "CPI slow path should succeed: {:?}", result);

        let data = svm.get_account(&envelope_addr).unwrap().data;
        let env: &Envelope = bytemuck::from_bytes(&data[..core::mem::size_of::<Envelope>()]);
        assert_eq!(env.authority_aux_sequence, 1);
        assert_eq!(env.auxiliary_data[0], 0xCC);
        assert_eq!(env.auxiliary_data[255], 0xDD);
    }

    /// CPI via byte_writer 0x02: UpdateAuxiliaryDelegated
    #[test]
    fn test_cpi_delegated_via_byte_writer() {
        let mut svm = setup_svm();
        svm.add_program_from_file(BYTE_WRITER_ID, BYTE_WRITER_SO_PATH)
            .expect("byte_writer .so not found");

        let authority_kp = Keypair::new();
        let delegation_kp = Keypair::new();
        let delegation_addr = delegation_kp.pubkey();
        let padding_kp = Keypair::new();
        let padding_addr = padding_kp.pubkey();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&delegation_addr, 1_000_000_000).unwrap();
        // program_bitmask: all writable for delegated program
        svm.set_account(
            envelope_addr,
            make_delegated_envelope(
                &authority_kp.pubkey(),
                &delegation_addr,
                Mask::ALL_WRITABLE,
                Mask::ALL_BLOCKED,
            ),
        )
        .unwrap();
        svm.set_account(padding_addr, create_funded_account(0))
            .unwrap();

        let mut aux_data = [0u8; 256];
        aux_data[0] = 0xEE;
        let ix_data = byte_writer_delegated_ix_data(1, &aux_data);

        let instruction = Instruction::new_with_bytes(
            BYTE_WRITER_ID,
            &ix_data,
            vec![
                AccountMeta::new(envelope_addr, false),
                AccountMeta::new_readonly(delegation_addr, true),
                AccountMeta::new_readonly(padding_addr, false),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&delegation_addr),
            &[&delegation_kp],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(tx);
        assert!(result.is_ok(), "CPI delegated should succeed: {:?}", result);

        let data = svm.get_account(&envelope_addr).unwrap().data;
        let env: &Envelope = bytemuck::from_bytes(&data[..core::mem::size_of::<Envelope>()]);
        assert_eq!(env.program_aux_sequence, 1);
        assert_eq!(env.auxiliary_data[0], 0xEE);
    }

    /// CPI via byte_writer 0x03: UpdateAuxiliaryForce
    #[test]
    fn test_cpi_force_via_byte_writer() {
        let mut svm = setup_svm();
        svm.add_program_from_file(BYTE_WRITER_ID, BYTE_WRITER_SO_PATH)
            .expect("byte_writer .so not found");

        let authority_kp = Keypair::new();
        let authority_addr = authority_kp.pubkey();
        let delegation_kp = Keypair::new();
        let delegation_addr = delegation_kp.pubkey();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&authority_addr, 1_000_000_000).unwrap();
        svm.set_account(
            envelope_addr,
            make_delegated_envelope(
                &authority_addr,
                &delegation_addr,
                Mask::ALL_WRITABLE,
                Mask::ALL_WRITABLE,
            ),
        )
        .unwrap();
        svm.set_account(delegation_addr, create_funded_account(0))
            .unwrap();

        let mut aux_data = [0u8; 256];
        aux_data[0] = 0xFF;
        aux_data[127] = 0xAA;
        let ix_data = byte_writer_force_ix_data(1, 1, &aux_data);

        let instruction = Instruction::new_with_bytes(
            BYTE_WRITER_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(authority_addr, true),
                AccountMeta::new(envelope_addr, false),
                AccountMeta::new_readonly(delegation_addr, true),
                AccountMeta::new_readonly(PROGRAM_ID, false),
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority_addr),
            &[&authority_kp, &delegation_kp],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(tx);
        assert!(result.is_ok(), "CPI force should succeed: {:?}", result);

        let data = svm.get_account(&envelope_addr).unwrap().data;
        let env: &Envelope = bytemuck::from_bytes(&data[..core::mem::size_of::<Envelope>()]);
        assert_eq!(env.authority_aux_sequence, 1);
        assert_eq!(env.program_aux_sequence, 1);
        assert_eq!(env.auxiliary_data[0], 0xFF);
        assert_eq!(env.auxiliary_data[127], 0xAA);
    }

    /// Attack: UpdateAuxiliaryDelegated with wrong delegation authority → c_u_soon rejects
    #[test]
    fn test_cpi_attack_wrong_delegation_authority() {
        let mut svm = setup_svm();
        svm.add_program_from_file(ATTACKER_PROBE_ID, ATTACKER_PROBE_SO_PATH)
            .expect("attacker_probe .so not found; run make build-sbf-test-programs first");

        let authority_kp = Keypair::new();
        let real_delegation_kp = Keypair::new();
        let wrong_delegation_kp = Keypair::new();
        let wrong_delegation_addr = wrong_delegation_kp.pubkey();
        let padding_addr = Address::new_unique();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&wrong_delegation_addr, 1_000_000_000).unwrap();
        svm.set_account(
            envelope_addr,
            make_delegated_envelope(
                &authority_kp.pubkey(),
                &real_delegation_kp.pubkey(),
                Mask::ALL_WRITABLE,
                Mask::ALL_BLOCKED,
            ),
        )
        .unwrap();
        svm.set_account(padding_addr, create_funded_account(0))
            .unwrap();

        let aux_data = [0u8; 256];
        let ix_data = attacker_wrong_delegation_authority(1, &aux_data);
        let instruction = Instruction::new_with_bytes(
            ATTACKER_PROBE_ID,
            &ix_data,
            vec![
                AccountMeta::new(envelope_addr, false), // [0] envelope
                AccountMeta::new_readonly(wrong_delegation_addr, true), // [1] wrong delegation, signer
                AccountMeta::new_readonly(padding_addr, false),         // [2] padding
                AccountMeta::new_readonly(PROGRAM_ID, false),           // [3] c_u_soon
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&wrong_delegation_addr),
            &[&wrong_delegation_kp],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(tx);
        assert!(
            result.is_err(),
            "Attack with wrong delegation authority should be rejected"
        );
    }

    /// Attack: Fast path CPI with stale sequence → c_u_soon rejects
    #[test]
    fn test_cpi_attack_stale_sequence() {
        let mut svm = setup_svm();
        svm.add_program_from_file(ATTACKER_PROBE_ID, ATTACKER_PROBE_SO_PATH)
            .expect("attacker_probe .so not found; run make build-sbf-test-programs first");

        let authority_kp = Keypair::new();
        let authority_addr = authority_kp.pubkey();
        let envelope_addr = Address::new_unique();

        svm.airdrop(&authority_addr, 1_000_000_000).unwrap();
        // Envelope already at sequence 5
        svm.set_account(envelope_addr, make_envelope(&authority_addr, 5))
            .unwrap();

        // Attack: try sequence 5 (== current, not strictly greater) → rejected
        let ix_data = attacker_stale_sequence(0, 5, &[0xAB]);
        let instruction = Instruction::new_with_bytes(
            ATTACKER_PROBE_ID,
            &ix_data,
            vec![
                AccountMeta::new_readonly(authority_addr, true), // [0] authority, signer
                AccountMeta::new(envelope_addr, false),          // [1] envelope, writable
                AccountMeta::new_readonly(PROGRAM_ID, false),    // [2] c_u_soon
            ],
        );

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&authority_addr),
            &[&authority_kp],
            svm.latest_blockhash(),
        );

        let result = svm.send_transaction(tx);
        assert!(
            result.is_err(),
            "Attack with stale sequence should be rejected"
        );
    }
}
