//! End-to-end key-attestation chain validation against checked-in vectors.
//! Feature-gated and **skip-if-absent**, the same posture as
//! `appattest_vectors.rs`: the vectors live under `test-vectors/keyattest/`.
//! When that directory is not present, these tests return early with a notice
//! rather than failing to build or run.
//!
//! These are the only tests that drive the full multi-cert walk end to end:
//! validity windows, the chain-extension defence, signature linkage, and the
//! anchor to a pinned Google root. See `test-vectors/keyattest/README.md`.
#![cfg(feature = "keyattest")]

use std::path::PathBuf;

use octet_attest_verify::keyattest::{
    verify_key_attestation, verify_key_attestation_with, AttestMode, KeyAttestOptions, SecurityLevel,
};
use octet_attest_verify::AttestError;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/keyattest")
}

fn read_chain(sub: &str, files: &[&str]) -> Option<Vec<Vec<u8>>> {
    let d = dir().join(sub);
    let paths: Vec<PathBuf> = files.iter().map(|f| d.join(f)).collect();
    if !paths.iter().all(|p| p.exists()) {
        eprintln!(
            "skipping: no key-attestation vector in {} \
             (see test-vectors/keyattest/README.md)",
            d.display()
        );
        return None;
    }
    Some(paths.iter().map(|p| std::fs::read(p).expect("read cert")).collect())
}

/// A genuine chain from a REAL device must be ACCEPTED — the guardrail on the
/// chain-extension fix. This is a Sony Xperia 10 III (Android 13 / sdk33, TEE, EC),
/// captured in Google's own `android/keyattestation` corpus, where its leaf's
/// direct issuer (the per-device batch key) is `CA:FALSE` with keyUsage
/// `digitalSignature` only. The FIRST version of this fix required issuers to
/// be CAs and rejected exactly this chain with `KeyAttestIssuerNotCa`, which is
/// why the fix was redesigned to Google's own model: constrain the attestation
/// extension's POSITION, not the CA flags.
#[test]
fn genuine_non_ca_batch_device_is_accepted() {
    let Some(chain) = read_chain(
        "real/sony_xperia10iii_sdk33_tee_ec",
        &["cert0.der", "cert1.der", "cert2.der"],
    ) else {
        return;
    };
    // The leaf's real attestationChallenge (32 bytes) and TEE security level;
    // the leaf is valid 1970-2106, the intermediates 2018-2028, so `now` sits
    // inside every window.
    let challenge = hex(b"3EAFE4D5DD0090DE5A42B432B42481AF5CE29963656B2584C59A492DE16D00C9");
    let att = verify_key_attestation(&chain, &challenge, 1_700_000_000, None, AttestMode::Proof)
        .expect("a genuine non-CA-batch device chain must verify");
    assert!(!att.leaf_pubkey_sec1.is_empty());
    assert!(att.app_identity.is_some());
}

/// A spread of genuine device chains from Google's `android/keyattestation`
/// corpus must clear the path checks and anchor. Each has the non-CA batch
/// issuer that the first (RFC 5280 CA-flag) design wrongly rejected, and
/// together they lock down BOTH pinned roots (the RSA `f92009…` and the EC
/// `Key Attestation CA1`), TEE + StrongBox, and the RKP intermediate shape.
///
/// The assertion is `AttestChallengeMismatch`: we do not hold each device's
/// server challenge, and that gate is the FIRST thing after the full path walk
/// (validity, chain-extension check, signature linkage, anchor) and the leaf
/// key-description parse. Reaching it proves every relevant check passed;
/// a regression would surface as `KeyAttestChainExtension`, `KeyAttestNotAnchored`,
/// `CertExpired` or a signature error instead. Each chain carries a fixed `now`
/// inside its (short-lived) batch-cert window, so the vectors are deterministic.
#[test]
fn genuine_corpus_chains_clear_the_path_checks() {
    // (subdir, cert count, now inside the batch-cert validity window)
    let cases: &[(&str, &[&str], u64)] = &[
        ("real/akita_sdk34_tee_ec",
         &["cert0.der", "cert1.der", "cert2.der", "cert3.der"], 1_727_237_961),
        ("real/caiman_sdk36_sb_ec_rkp",
         &["cert0.der", "cert1.der", "cert2.der", "cert3.der"], 1_759_173_116),
        ("real/tegu_sdk36_tee_ec_2026root",
         &["cert0.der", "cert1.der", "cert2.der", "cert3.der"], 1_772_324_168),
    ];
    for (sub, files, now) in cases {
        let Some(chain) = read_chain(sub, files) else { continue };
        let r = verify_key_attestation(&chain, b"dummy-challenge", *now, None, AttestMode::Proof);
        assert_eq!(
            r.err(),
            Some(AttestError::AttestChallengeMismatch),
            "{sub}: a genuine chain must clear the path checks and reach the challenge \
             gate, not fail a path check",
        );
    }
}

/// The chain-extension attack must be REJECTED: a chain where a NON-leaf cert carries the
/// key-attestation extension. In the real attack that cert is a genuine device
/// leaf (which carries its own extension) used to sign a forged sub-cert; here
/// the issuer is a synthetic cert bearing the attestation OID that signs a
/// forged leaf. The rejection must be `KeyAttestChainExtension` specifically,
/// which proves the extension-position check runs BEFORE the anchor step — a
/// real attack chain does anchor, so an earlier `KeyAttestNotAnchored` would
/// mean the defence never fired on it.
#[test]
fn attestation_extension_on_a_non_leaf_cert_is_rejected() {
    let Some(chain) = read_chain(
        "forged",
        &["leaf.der", "issuer_with_attestation_ext.der"],
    ) else {
        return;
    };
    let err = verify_key_attestation(&chain, b"anything", 1_700_000_000, None, AttestMode::Proof)
        .expect_err("an attestation extension on a non-leaf cert must be rejected");
    assert_eq!(err, AttestError::KeyAttestChainExtension);
}

/// The genuine corpus chains (subdir, files, a `now` inside every window).
const CORPUS: &[(&str, &[&str], u64)] = &[
    ("real/sony_xperia10iii_sdk33_tee_ec", &["cert0.der", "cert1.der", "cert2.der"], 1_700_000_000),
    ("real/akita_sdk34_tee_ec", &["cert0.der", "cert1.der", "cert2.der", "cert3.der"], 1_727_237_961),
    ("real/caiman_sdk36_sb_ec_rkp", &["cert0.der", "cert1.der", "cert2.der", "cert3.der"], 1_759_173_116),
    ("real/tegu_sdk36_tee_ec_2026root", &["cert0.der", "cert1.der", "cert2.der", "cert3.der"], 1_772_324_168),
];

/// The stateless options a verifier uses when it doesn't know the key's
/// challenge: no challenge, no boot requirement, a revocation list.
fn no_challenge(revoked: &[Vec<u8>]) -> KeyAttestOptions<'_> {
    KeyAttestOptions {
        expected_challenge: None,
        expected_apps: &[],
        revoked_serials: revoked,
        require_verified_boot: false,
        allow_software: false,
    }
}

/// Without an expected challenge, every genuine chain verifies in full and
/// returns its leaf's challenge, which then verifies as the expected one.
#[test]
fn genuine_chains_verify_without_a_challenge_and_return_it() {
    for (sub, files, now) in CORPUS {
        let Some(chain) = read_chain(sub, files) else { continue };
        let att = verify_key_attestation_with(&chain, *now, &no_challenge(&[]))
            .unwrap_or_else(|e| panic!("{sub}: {e:?}"));
        assert!(!att.attestation_challenge.is_empty(), "{sub}");
        assert_ne!(att.security_level, SecurityLevel::Software, "{sub}");
        let again = verify_key_attestation(&chain, &att.attestation_challenge, *now, None, AttestMode::Proof)
            .unwrap_or_else(|e| panic!("{sub}: the returned challenge must verify: {e:?}"));
        assert_eq!(again.leaf_pubkey_sec1, att.leaf_pubkey_sec1);
    }
    if let Some(chain) = read_chain(CORPUS[0].0, CORPUS[0].1) {
        let att = verify_key_attestation_with(&chain, CORPUS[0].2, &no_challenge(&[])).unwrap();
        assert_eq!(
            att.attestation_challenge,
            hex(b"3EAFE4D5DD0090DE5A42B432B42481AF5CE29963656B2584C59A492DE16D00C9")
        );
    }
}

/// A revoked serial anywhere in the chain fails, with or without the boot
/// requirement, and serials compare without DER sign padding. An unrelated
/// serial changes nothing. The boot state is returned without being enforced.
#[test]
fn revocation_applies_without_the_boot_requirement() {
    use x509_cert::der::Decode;
    for (sub, files, now) in CORPUS {
        let Some(chain) = read_chain(sub, files) else { continue };
        let ok = verify_key_attestation_with(&chain, *now, &no_challenge(&[vec![0x7f; 20]]))
            .unwrap_or_else(|e| panic!("{sub}: {e:?}"));
        assert!(ok.root_of_trust.is_some(), "{sub}: the RootOfTrust is returned");
        for cert in &chain {
            let serial = x509_cert::Certificate::from_der(cert)
                .unwrap()
                .tbs_certificate
                .serial_number
                .as_bytes()
                .to_vec();
            let mut padded = vec![0u8];
            padded.extend_from_slice(&serial);
            for revoked in [serial, padded] {
                assert_eq!(
                    verify_key_attestation_with(&chain, *now, &no_challenge(&[revoked])).err(),
                    Some(AttestError::AttestationRevoked),
                    "{sub}",
                );
            }
        }
    }
}

/// Simple hex decode for the fixed challenge literal above.
fn hex(s: &[u8]) -> Vec<u8> {
    fn nib(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("bad hex"),
        }
    }
    s.chunks(2).map(|c| (nib(c[0]) << 4) | nib(c[1])).collect()
}
