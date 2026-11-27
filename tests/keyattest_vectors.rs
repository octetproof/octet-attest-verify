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
    verify_key_attestation, verify_key_attestation_report, verify_key_attestation_with, AttestMode,
    KeyAttestOptions, Provisioning, RootOfTrust, SecurityLevel, VerifiedBootState,
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

/// The read-only chain details, pinned for every genuine chain. The OS and patch
/// levels were checked against `openssl asn1parse` of each leaf's extension;
/// the serial and issuer are `chain[1]`'s as `openssl x509` prints them. The
/// Sony chain is a factory keybox (`serialNumber=` intermediates under the RSA
/// root); the Pixels are RKP (`Droid CA2` under either root).
#[test]
fn chain_details_of_the_genuine_chains() {
    struct Want {
        provisioning: Provisioning,
        serial: &'static str,
        issuer: &'static str,
        level: SecurityLevel,
        os: u32,
        os_patch: u32,
        patch: u32, // vendor and boot patch levels (equal on these devices)
        rot: RootOfTrust,
    }
    let verified = RootOfTrust { device_locked: true, verified_boot_state: VerifiedBootState::Verified };
    let wants = [
        Want { provisioning: Provisioning::Factory, serial: "16580768335559031605", issuer: "SERIALNUMBER=87f4514475ba0a2b",
               level: SecurityLevel::TrustedEnvironment, os: 130000, os_patch: 202307, patch: 20230701, rot: verified },
        Want { provisioning: Provisioning::RemotelyProvisioned, serial: "4f47dffaecc3f58346fb7815514e0dcc", issuer: "CN=Droid CA3,O=Google LLC",
               level: SecurityLevel::TrustedEnvironment, os: 140000, os_patch: 202408, patch: 20240805,
               rot: RootOfTrust { device_locked: false, verified_boot_state: VerifiedBootState::Unverified } },
        Want { provisioning: Provisioning::RemotelyProvisioned, serial: "65d2949536924da695f5ae1eb290cd4d", issuer: "CN=Droid CA3,O=Google LLC",
               level: SecurityLevel::StrongBox, os: 160000, os_patch: 202511, patch: 20251105, rot: verified },
        Want { provisioning: Provisioning::RemotelyProvisioned, serial: "2c85cdc15c3042f25698906669c35137", issuer: "CN=Droid CA3,O=Google LLC",
               level: SecurityLevel::TrustedEnvironment, os: 160000, os_patch: 202602, patch: 20260205, rot: verified },
    ];
    for ((sub, files, now), want) in CORPUS.iter().zip(&wants) {
        let Some(chain) = read_chain(sub, files) else { continue };
        let opts = no_challenge(&[]);
        let report = verify_key_attestation_report(&chain, *now, &opts);
        // The report's result is exactly verify_key_attestation_with's.
        let plain = verify_key_attestation_with(&chain, *now, &opts);
        assert_eq!(report.result.as_ref().err(), plain.as_ref().err(), "{sub}");
        let att = report.result.as_ref().unwrap_or_else(|e| panic!("{sub}: {e}"));
        let d = report.details.as_ref().unwrap_or_else(|| panic!("{sub}: details"));
        assert_eq!(d.provisioning, want.provisioning, "{sub}: provisioning");
        assert_eq!(d.attestation_cert_serial.as_deref(), Some(want.serial), "{sub}: serial");
        assert_eq!(d.attestation_cert_issuer.as_deref(), Some(want.issuer), "{sub}: issuer");
        assert_eq!(d.attestation_security_level, Some(want.level), "{sub}: security level");
        assert_eq!(d.os_version, Some(want.os), "{sub}: osVersion");
        assert_eq!(d.os_patch_level, Some(want.os_patch), "{sub}: osPatchLevel");
        assert_eq!(d.vendor_patch_level, Some(want.patch), "{sub}: vendorPatchLevel");
        assert_eq!(d.boot_patch_level, Some(want.patch), "{sub}: bootPatchLevel");
        assert_eq!(d.root_of_trust, Some(want.rot), "{sub}: root of trust");
        assert_eq!(d.root_of_trust, att.root_of_trust, "{sub}: same root of trust as the result");
        assert_eq!(d.leaf_pubkey_sec1.as_deref(), Some(att.leaf_pubkey_sec1.as_slice()), "{sub}: leaf key");
    }
}

/// A refused chain still reports what it says. The akita phone's bootloader is
/// unlocked (verified boot Unverified), so Bootstrap refuses it; the report
/// carries the refusal and the root of trust that caused it. Revocation and a
/// wrong challenge are refusals too, with details. A chain that fails before
/// the policy checks (here: outside its validity window) has none.
#[test]
fn refused_chains_carry_their_details() {
    let (sub, files, now) = CORPUS[1];
    let Some(chain) = read_chain(sub, files) else { return };
    let mut bootstrap = no_challenge(&[]);
    bootstrap.require_verified_boot = true;
    let r = verify_key_attestation_report(&chain, now, &bootstrap);
    assert_eq!(r.result.as_ref().err(), Some(&AttestError::AttestationUnverifiedBoot));
    let rot = r.details.expect("details on a boot refusal").root_of_trust.expect("root of trust");
    assert_eq!(rot, RootOfTrust { device_locked: false, verified_boot_state: VerifiedBootState::Unverified });

    let serial = x509_serial(&chain[1]);
    let r = verify_key_attestation_report(&chain, now, &no_challenge(&[serial]));
    assert_eq!(r.result.as_ref().err(), Some(&AttestError::AttestationRevoked));
    assert!(r.details.is_some(), "details on a revocation");

    let mut wrong = no_challenge(&[]);
    wrong.expected_challenge = Some(b"not-the-challenge");
    let r = verify_key_attestation_report(&chain, now, &wrong);
    assert_eq!(r.result.as_ref().err(), Some(&AttestError::AttestChallengeMismatch));
    assert!(r.details.is_some(), "details on a challenge mismatch");

    let r = verify_key_attestation_report(&chain, 4_000_000_000, &no_challenge(&[]));
    assert_eq!(r.result.as_ref().err(), Some(&AttestError::CertExpired));
    assert!(r.details.is_none(), "no details for a chain that did not verify");
}

fn x509_serial(der: &[u8]) -> Vec<u8> {
    use x509_cert::der::Decode;
    x509_cert::Certificate::from_der(der).unwrap().tbs_certificate.serial_number.as_bytes().to_vec()
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
