// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Bundle seal/open integration tests (vault-vh1 definition-of-done).
//!
//! These exercise the full container: AES-256-GCM payload + KEK-wrap, the JSON
//! container with base64-nopad fields, header-AAD binding (tamper → auth fail),
//! multi-slot recovery of one KEK, and the no-slot-opens fail-closed path.
//! Argon2id uses a small profile here ONLY for test speed (production uses
//! 64 MiB / t=3 / p=1); the passphrase/bip39 method tests note the same.

use super::cred::{BackendCred, CredBundle};
use super::format::{Argon2Params, MethodKind};
use super::unlock::bip39::Bip39Method;
use super::unlock::passphrase::PassphraseMethod;
use super::{
    DepositContributor, DepositStatus, MethodRegistry, SealError, SlotSpec, add_slot,
    apply_authorized_deposits, create_signed_record, format, open_bundle, promote_deposits,
    remove_slot, reseal_payload, reseal_payload_bump_epoch, seal, verify_epoch_sidecar,
    write_epoch_sidecar,
};
use std::collections::{BTreeMap, BTreeSet};
use zero_secrets::{SecretBytes, SecretString};
use zeroize::Zeroizing;

/// Tiny Argon2id profile: TEST ONLY (production uses 64 MiB / t=3 / p=1).
const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 256,
    t_cost: 1,
    p_cost: 1,
};

fn sample_payload() -> CredBundle {
    let mut b = CredBundle::empty();
    b.set(
        "vault-transit",
        BackendCred::VaultToken {
            token: SecretString::new("s.supersecret".to_string()),
            addr: Some("http://127.0.0.1:8200".to_string()),
        },
    );
    b
}

fn assert_token(payload: &CredBundle, backend: &str, expect: &str) {
    let got = match payload.backends.get(backend) {
        Some(BackendCred::VaultToken { token, .. }) => Some(token.expose_secret()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expect),
        "expected a VaultToken `{expect}` for {backend}"
    );
}

fn deposit_payload(allowed_backend_ids: &[&str]) -> (CredBundle, Zeroizing<[u8; 32]>) {
    let mut payload = sample_payload();
    payload.ensure_deposit_identity();
    let signer = Zeroizing::new([9u8; 32]);
    let public = super::contributor_public_token(&signer);
    payload.deposit.contributors = BTreeMap::from([(
        public.clone(),
        DepositContributor {
            public_key: public,
            allowed_backend_ids: allowed_backend_ids
                .iter()
                .map(|id| (*id).to_string())
                .collect(),
        },
    )]);
    (payload, signer)
}

#[test]
fn bip39_seal_unseal_round_trip() {
    let phrase = Bip39Method::generate_phrase().unwrap();
    let method = Bip39Method::with_params(phrase, FAST);
    let spec = SlotSpec {
        method: &method,
        label: "break-glass".into(),
    };
    let payload = sample_payload();
    let file = seal(&payload, std::slice::from_ref(&spec)).unwrap();

    // Container sanity: magic + base64-nopad JSON.
    assert!(file.starts_with(format::MAGIC));
    let parsed = format::decode(&file).unwrap();

    let registry = MethodRegistry::new().with(&method);
    let opened = open_bundle(&parsed, &registry).unwrap();
    assert_token(&opened, "vault-transit", "s.supersecret");
}

#[test]
fn passphrase_seal_unseal_round_trip() {
    let method = PassphraseMethod::with_params(Zeroizing::new(b"test-pass".to_vec()), FAST);
    let spec = SlotSpec {
        method: &method,
        label: "passphrase".into(),
    };
    let file = seal(&sample_payload(), std::slice::from_ref(&spec)).unwrap();
    let parsed = format::decode(&file).unwrap();
    let registry = MethodRegistry::new().with(&method);

    let opened = open_bundle(&parsed, &registry).unwrap();
    assert_token(&opened, "vault-transit", "s.supersecret");
}

#[test]
fn header_tamper_breaks_aead() {
    let method = PassphraseMethod::with_params(Zeroizing::new(b"p".to_vec()), FAST);
    let spec = SlotSpec {
        method: &method,
        label: "passphrase".into(),
    };
    let file = seal(&sample_payload(), std::slice::from_ref(&spec)).unwrap();
    let mut parsed = format::decode(&file).unwrap();

    // Flip the epoch byte in BOTH the parsed header and the literal AAD bytes so
    // the container still parses (header == header_b64), but the AAD no longer
    // matches what the payload/slots were sealed under.
    parsed.body.header.epoch ^= 0xFF;
    let tampered_aad = parsed.body.header.to_aad_bytes().unwrap();
    parsed.body.header_b64 = format::B64Bytes(tampered_aad);

    let registry = MethodRegistry::new().with(&method);
    // The slot wrap AAD (header || slot_id) no longer authenticates -> the slot
    // fails, and no slot opens -> fail closed.
    assert!(matches!(
        open_bundle(&parsed, &registry),
        Err(SealError::NoSlotOpened)
    ));
}

#[test]
fn payload_tamper_breaks_aead() {
    let method = PassphraseMethod::with_params(Zeroizing::new(b"p".to_vec()), FAST);
    let spec = SlotSpec {
        method: &method,
        label: "passphrase".into(),
    };
    let file = seal(&sample_payload(), std::slice::from_ref(&spec)).unwrap();
    let mut parsed = format::decode(&file).unwrap();

    // Corrupt one payload ciphertext byte -> AEAD auth fails on decrypt (the slot
    // still recovers the KEK, so this surfaces as AuthFailed, not NoSlotOpened).
    if let Some(b) = parsed.body.payload.ciphertext.0.first_mut() {
        *b ^= 0x01;
    }
    let registry = MethodRegistry::new().with(&method);
    assert!(matches!(
        open_bundle(&parsed, &registry),
        Err(SealError::AuthFailed)
    ));
}

#[test]
fn multi_slot_either_recovers_same_kek() {
    // Two slots (passphrase + bip39) wrap the same master KEK; either opens the bundle.
    let passphrase = PassphraseMethod::with_params(Zeroizing::new(b"passphrase".to_vec()), FAST);
    let phrase = Bip39Method::generate_phrase().unwrap();
    let bip = Bip39Method::with_params(phrase, FAST);
    let specs = [
        SlotSpec {
            method: &passphrase,
            label: "passphrase".into(),
        },
        SlotSpec {
            method: &bip,
            label: "break-glass".into(),
        },
    ];
    let file = seal(&sample_payload(), &specs).unwrap();
    let parsed = format::decode(&file).unwrap();
    assert_eq!(parsed.body.slots.len(), 2);

    // Only the bip39 method available -> opens via slot 1.
    let only_bip = MethodRegistry::new().with(&bip);
    assert_token(
        &open_bundle(&parsed, &only_bip).unwrap(),
        "vault-transit",
        "s.supersecret",
    );

    // Only the passphrase method available -> opens via slot 0, same payload.
    let only_passphrase = MethodRegistry::new().with(&passphrase);
    assert_token(
        &open_bundle(&parsed, &only_passphrase).unwrap(),
        "vault-transit",
        "s.supersecret",
    );
}

#[test]
fn no_slot_opens_fails_closed() {
    let method = Bip39Method::with_params(Bip39Method::generate_phrase().unwrap(), FAST);
    let spec = SlotSpec {
        method: &method,
        label: "break-glass".into(),
    };
    let file = seal(&sample_payload(), std::slice::from_ref(&spec)).unwrap();
    let parsed = format::decode(&file).unwrap();

    // Empty registry -> nothing can open the (bip39) slot -> fail closed.
    let empty = MethodRegistry::new();
    assert!(matches!(
        open_bundle(&parsed, &empty),
        Err(SealError::NoSlotOpened)
    ));
}

#[test]
fn wrong_bip39_phrase_fails_closed() {
    let method = Bip39Method::with_params(Bip39Method::generate_phrase().unwrap(), FAST);
    let spec = SlotSpec {
        method: &method,
        label: "break-glass".into(),
    };
    let file = seal(&sample_payload(), std::slice::from_ref(&spec)).unwrap();
    let parsed = format::decode(&file).unwrap();

    // A registry holding a *different* phrase cannot open the slot.
    let wrong = Bip39Method::with_params(Bip39Method::generate_phrase().unwrap(), FAST);
    let registry = MethodRegistry::new().with(&wrong);
    assert!(matches!(
        open_bundle(&parsed, &registry),
        Err(SealError::NoSlotOpened)
    ));
}

#[test]
fn add_then_remove_slot() {
    let passphrase = PassphraseMethod::with_params(Zeroizing::new(b"passphrase".to_vec()), FAST);
    let phrase = Bip39Method::generate_phrase().unwrap();
    let bip = Bip39Method::with_params(phrase, FAST);

    // Seal with the passphrase slot only.
    let file = seal(
        &sample_payload(),
        &[SlotSpec {
            method: &passphrase,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let parsed = format::decode(&file).unwrap();

    // Add a bip39 slot (open via passphrase, payload untouched).
    let passphrase_reg = MethodRegistry::new().with(&passphrase);
    let file2 = add_slot(
        &parsed,
        &passphrase_reg,
        &SlotSpec {
            method: &bip,
            label: "break-glass".into(),
        },
    )
    .unwrap();
    let parsed2 = format::decode(&file2).unwrap();
    assert_eq!(parsed2.body.slots.len(), 2);

    // The new bip39 slot opens to the SAME payload (KEK was preserved).
    let bip_reg = MethodRegistry::new().with(&bip);
    assert_token(
        &open_bundle(&parsed2, &bip_reg).unwrap(),
        "vault-transit",
        "s.supersecret",
    );

    // Remove the passphrase slot; the bip39 slot still opens.
    let passphrase_slot_id = parsed2
        .body
        .slots
        .iter()
        .find(|s| s.method == MethodKind::Passphrase)
        .unwrap()
        .slot_id;
    let file3 = remove_slot(&parsed2, passphrase_slot_id).unwrap();
    let parsed3 = format::decode(&file3).unwrap();
    assert_eq!(parsed3.body.slots.len(), 1);
    assert_token(
        &open_bundle(&parsed3, &bip_reg).unwrap(),
        "vault-transit",
        "s.supersecret",
    );
}

#[test]
fn refuse_remove_last_slot() {
    let passphrase = PassphraseMethod::with_params(Zeroizing::new(b"p".to_vec()), FAST);
    let file = seal(
        &sample_payload(),
        &[SlotSpec {
            method: &passphrase,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let parsed = format::decode(&file).unwrap();
    assert!(matches!(
        remove_slot(&parsed, parsed.body.slots[0].slot_id),
        Err(SealError::LastSlot)
    ));
}

#[test]
fn set_cred_reseal_round_trip() {
    let passphrase = PassphraseMethod::with_params(Zeroizing::new(b"p".to_vec()), FAST);
    let file = seal(
        &sample_payload(),
        &[SlotSpec {
            method: &passphrase,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let parsed = format::decode(&file).unwrap();
    let registry = MethodRegistry::new().with(&passphrase);

    // Rotate the token via set-cred.
    let mut new_payload = sample_payload();
    new_payload.set(
        "vault-transit",
        BackendCred::VaultToken {
            token: SecretString::new("s.rotated".to_string()),
            addr: None,
        },
    );
    let file2 = reseal_payload(&parsed, &registry, &new_payload).unwrap();
    let parsed2 = format::decode(&file2).unwrap();

    // The ciphertext changed (fresh nonce); the slot still opens to the new cred.
    assert_ne!(
        parsed.body.payload.ciphertext.0,
        parsed2.body.payload.ciphertext.0
    );
    assert_token(
        &open_bundle(&parsed2, &registry).unwrap(),
        "vault-transit",
        "s.rotated",
    );
}

#[test]
fn epoch_bump_full_reseal_rewraps_slots() {
    let passphrase = PassphraseMethod::with_params(Zeroizing::new(b"p".to_vec()), FAST);
    let file = seal(
        &sample_payload(),
        &[SlotSpec {
            method: &passphrase,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let parsed = format::decode(&file).unwrap();
    let registry = MethodRegistry::new().with(&passphrase);

    let mut new_payload = sample_payload();
    new_payload.set(
        "vault-transit",
        BackendCred::VaultToken {
            token: SecretString::new("s.epoch2".to_string()),
            addr: None,
        },
    );
    let file2 = reseal_payload_bump_epoch(&parsed, &registry, &new_payload).unwrap();
    let parsed2 = format::decode(&file2).unwrap();

    assert_eq!(parsed2.body.header.epoch, parsed.body.header.epoch + 1);
    assert_token(
        &open_bundle(&parsed2, &registry).unwrap(),
        "vault-transit",
        "s.epoch2",
    );
    assert!(
        open_bundle(&parsed, &registry).is_ok(),
        "old bundle is still cryptographically valid; sidecar enforces rollback"
    );
}

#[test]
fn epoch_sidecar_refuses_stale_bundle() {
    let passphrase = PassphraseMethod::with_params(Zeroizing::new(b"p".to_vec()), FAST);
    let file = seal(
        &sample_payload(),
        &[SlotSpec {
            method: &passphrase,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let parsed = format::decode(&file).unwrap();
    let path = std::env::temp_dir().join(format!(
        "basil-epoch-sidecar-{}-{}.epoch",
        std::process::id(),
        parsed.body.header.created_unix
    ));

    write_epoch_sidecar(&path, parsed.body.header.epoch + 1).unwrap();
    let err = verify_epoch_sidecar(&parsed, &path).expect_err("stale bundle refused");
    let _ = std::fs::remove_file(&path);
    assert!(matches!(err, SealError::Format(msg) if msg.contains("epoch rollback")));
}

#[test]
fn keystore_creds_seal_unseal_round_trip() {
    use zero_secrets::SecretArray;

    // A sealed bundle carrying the two key-store bootstrap creds: the db-keystore
    // DEK and the 1Password provider config. Unlocking must recover both intact.
    let mut payload = CredBundle::empty();
    let dek = [0x5au8; 32];
    payload.set(
        "db-keystore",
        BackendCred::DbKeystoreDek {
            dek: SecretArray::new(dek),
        },
    );
    payload.set(
        "onepassword",
        BackendCred::OnePassword {
            provider_uri: "onepassword://basil".to_string(),
            project: "basil-prod".to_string(),
            profile: "default".to_string(),
        },
    );

    let method = PassphraseMethod::with_params(Zeroizing::new(b"unlock-me".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let parsed = format::decode(&file).unwrap();
    let registry = MethodRegistry::new().with(&method);
    let opened = open_bundle(&parsed, &registry).unwrap();

    match opened.backends.get("db-keystore") {
        Some(BackendCred::DbKeystoreDek { dek: got }) => {
            assert_eq!(
                got.expose_secret(),
                &dek,
                "DEK must survive the seal round trip"
            );
        }
        other => panic!("wrong variant: {:?}", other.map(BackendCred::kind)),
    }
    match opened.backends.get("onepassword") {
        Some(BackendCred::OnePassword {
            provider_uri,
            project,
            profile,
        }) => {
            assert_eq!(provider_uri, "onepassword://basil");
            assert_eq!(project, "basil-prod");
            assert_eq!(profile, "default");
        }
        other => panic!("wrong variant: {:?}", other.map(BackendCred::kind)),
    }
}

#[test]
fn authorized_deposit_overlays_baseline() {
    let (mut payload, signer) = deposit_payload(&["vault-transit"]);
    let method = PassphraseMethod::with_params(Zeroizing::new(b"deposit-pass".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let mut parsed = format::decode(&file).unwrap();
    let recipient = payload.deposit_recipient().unwrap();
    let contributor = super::contributor_public_token(&signer);
    let replacement = BackendCred::VaultToken {
        token: SecretString::new("s.deposited".to_string()),
        addr: Some("http://127.0.0.1:8200".to_string()),
    };
    parsed.body.deposits.push(
        create_signed_record(
            &parsed.body.header,
            "vault-transit".to_string(),
            contributor,
            1,
            &recipient,
            &signer,
            &replacement,
        )
        .unwrap(),
    );

    let reviews = apply_authorized_deposits(&parsed, &mut payload);

    assert_eq!(reviews[0].status, DepositStatus::Effective);
    assert_token(&payload, "vault-transit", "s.deposited");
}

#[test]
fn oversized_deposit_log_drops_only_the_excess_tail() {
    let (mut payload, signer) = deposit_payload(&["vault-transit"]);
    let method = PassphraseMethod::with_params(Zeroizing::new(b"deposit-pass".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let mut parsed = format::decode(&file).unwrap();
    let recipient = payload.deposit_recipient().unwrap();
    let contributor = super::contributor_public_token(&signer);
    let replacement = BackendCred::VaultToken {
        token: SecretString::new("s.deposited".to_string()),
        addr: Some("http://127.0.0.1:8200".to_string()),
    };
    let valid = create_signed_record(
        &parsed.body.header,
        "vault-transit".to_string(),
        contributor,
        1,
        &recipient,
        &signer,
        &replacement,
    )
    .unwrap();
    parsed.body.deposits.push(valid.clone());
    // Flood the log one past the cap with junk records (the bumped seq breaks
    // each signature): a mass append must not invalidate the earlier deposit.
    for extra in 0..1024u64 {
        let mut junk = valid.clone();
        junk.seq = 2 + extra;
        parsed.body.deposits.push(junk);
    }

    let reviews = apply_authorized_deposits(&parsed, &mut payload);

    assert_eq!(reviews.len(), 1025);
    // The earliest record still verifies and applies...
    assert_eq!(reviews[0].status, DepositStatus::Effective);
    assert_token(&payload, "vault-transit", "s.deposited");
    // ...junk below the cap is rejected individually...
    assert!(
        reviews[1..1024]
            .iter()
            .all(|r| r.status == DepositStatus::BadSignature)
    );
    // ...and only the excess tail is dropped as log-too-large.
    assert_eq!(reviews[1024].status, DepositStatus::LogTooLarge);
}

#[test]
fn unauthorized_deposit_is_ignored() {
    let (mut payload, signer) = deposit_payload(&["other-backend"]);
    let method = PassphraseMethod::with_params(Zeroizing::new(b"deposit-pass".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let mut parsed = format::decode(&file).unwrap();
    let recipient = payload.deposit_recipient().unwrap();
    let contributor = super::contributor_public_token(&signer);
    parsed.body.deposits.push(
        create_signed_record(
            &parsed.body.header,
            "vault-transit".to_string(),
            contributor,
            1,
            &recipient,
            &signer,
            &BackendCred::VaultToken {
                token: SecretString::new("s.rejected".to_string()),
                addr: None,
            },
        )
        .unwrap(),
    );

    let reviews = apply_authorized_deposits(&parsed, &mut payload);

    assert_eq!(reviews[0].status, DepositStatus::UnauthorizedBackend);
    assert_token(&payload, "vault-transit", "s.supersecret");
}

#[test]
fn bad_signature_deposit_is_ignored() {
    let (mut payload, signer) = deposit_payload(&["vault-transit"]);
    let method = PassphraseMethod::with_params(Zeroizing::new(b"deposit-pass".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let mut parsed = format::decode(&file).unwrap();
    let recipient = payload.deposit_recipient().unwrap();
    let contributor = super::contributor_public_token(&signer);
    let mut record = create_signed_record(
        &parsed.body.header,
        "vault-transit".to_string(),
        contributor,
        1,
        &recipient,
        &signer,
        &BackendCred::VaultToken {
            token: SecretString::new("s.rejected".to_string()),
            addr: None,
        },
    )
    .unwrap();
    if let Some(byte) = record.signature.0.first_mut() {
        *byte ^= 0xFF;
    }
    parsed.body.deposits.push(record);

    let reviews = apply_authorized_deposits(&parsed, &mut payload);

    assert_eq!(reviews[0].status, DepositStatus::BadSignature);
    assert_token(&payload, "vault-transit", "s.supersecret");
}

#[test]
fn stale_epoch_deposit_is_ignored() {
    let (mut payload, signer) = deposit_payload(&["vault-transit"]);
    let method = PassphraseMethod::with_params(Zeroizing::new(b"deposit-pass".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let mut parsed = format::decode(&file).unwrap();
    let recipient = payload.deposit_recipient().unwrap();
    let contributor = super::contributor_public_token(&signer);
    let mut record = create_signed_record(
        &parsed.body.header,
        "vault-transit".to_string(),
        contributor,
        1,
        &recipient,
        &signer,
        &BackendCred::VaultToken {
            token: SecretString::new("s.rejected".to_string()),
            addr: None,
        },
    )
    .unwrap();
    record.epoch += 1;
    parsed.body.deposits.push(record);

    let reviews = apply_authorized_deposits(&parsed, &mut payload);

    assert_eq!(reviews[0].status, DepositStatus::StaleEpoch);
    assert_token(&payload, "vault-transit", "s.supersecret");
}

#[test]
fn lower_sequence_deposit_does_not_rollback_newer_deposit() {
    let (mut payload, signer) = deposit_payload(&["vault-transit"]);
    let method = PassphraseMethod::with_params(Zeroizing::new(b"deposit-pass".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let mut parsed = format::decode(&file).unwrap();
    let recipient = payload.deposit_recipient().unwrap();
    let contributor = super::contributor_public_token(&signer);
    parsed.body.deposits.push(
        create_signed_record(
            &parsed.body.header,
            "vault-transit".to_string(),
            contributor.clone(),
            2,
            &recipient,
            &signer,
            &BackendCred::VaultToken {
                token: SecretString::new("s.newer".to_string()),
                addr: None,
            },
        )
        .unwrap(),
    );
    parsed.body.deposits.push(
        create_signed_record(
            &parsed.body.header,
            "vault-transit".to_string(),
            contributor,
            1,
            &recipient,
            &signer,
            &BackendCred::VaultToken {
                token: SecretString::new("s.older".to_string()),
                addr: None,
            },
        )
        .unwrap(),
    );

    let reviews = apply_authorized_deposits(&parsed, &mut payload);

    assert_eq!(reviews[0].status, DepositStatus::Effective);
    assert_eq!(reviews[1].status, DepositStatus::Superseded);
    assert_token(&payload, "vault-transit", "s.newer");
}

#[test]
fn promote_commits_selected_deposit_and_prunes_log() {
    let (payload, signer) = deposit_payload(&["vault-transit"]);
    let method = PassphraseMethod::with_params(Zeroizing::new(b"deposit-pass".to_vec()), FAST);
    let file = seal(
        &payload,
        &[SlotSpec {
            method: &method,
            label: "passphrase".into(),
        }],
    )
    .unwrap();
    let mut parsed = format::decode(&file).unwrap();
    let recipient = payload.deposit_recipient().unwrap();
    let contributor = super::contributor_public_token(&signer);
    parsed.body.deposits.push(
        create_signed_record(
            &parsed.body.header,
            "vault-transit".to_string(),
            contributor,
            1,
            &recipient,
            &signer,
            &BackendCred::VaultToken {
                token: SecretString::new("s.promoted".to_string()),
                addr: None,
            },
        )
        .unwrap(),
    );
    let registry = MethodRegistry::new().with(&method);

    let (promoted_file, reviews) =
        promote_deposits(&parsed, &registry, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    let promoted = format::decode(&promoted_file).unwrap();
    let opened = open_bundle(&promoted, &registry).unwrap();

    assert_eq!(reviews[0].status, DepositStatus::Effective);
    assert_eq!(promoted.body.header.epoch, parsed.body.header.epoch + 1);
    assert!(promoted.body.deposits.is_empty());
    assert_token(&opened, "vault-transit", "s.promoted");
}

#[test]
fn cred_bundle_zeroizes_best_effort() {
    // Best-effort assertion that secret material is wiped. `unsafe` is forbidden
    // workspace-wide (so we can't inspect freed memory), so we verify the wipe
    // semantics directly via the `Zeroize` trait on a buffer holding the same
    // bytes a `BackendCred::Opaque` secret would carry, then confirm the cred's
    // secret field is `Zeroizing` (wiped on drop) by construction.
    use zeroize::Zeroize;
    let mut buf = b"s.zeroize-me".to_vec();
    buf.zeroize();
    assert!(
        buf.iter().all(|&b| b == 0),
        "Zeroize should wipe the buffer"
    );

    // The cred holds its secret in a zeroizing wrapper -> wiped on drop.
    let cred = BackendCred::Opaque {
        kind: "db-dek".into(),
        secret: SecretBytes::new(b"super-secret".to_vec()),
    };
    // Type-level guarantee: the secret field is SecretBytes.
    match &cred {
        BackendCred::Opaque { secret, .. } => {
            assert_eq!(secret.expose_secret(), b"super-secret");
        }
        _ => panic!("wrong variant"),
    }
}
