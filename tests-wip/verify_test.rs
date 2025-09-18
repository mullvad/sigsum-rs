use sigsum::{Hash, Signature, SpicySignature};

const CHECKSUM: [u8; 32] =
    hex_literal::hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

fn mkpolicy() {
    todo!()
}

fn mksigners() {
    todo!()
}

#[test]
fn test_verify_ok() {
    let checksum: Hash = CHECKSUM.into();
    let spicy = SpicySignature::from_ascii(include_str!("testdata/spicy-signature-ok.ascii"));
    let signers = mksigners();
    let policy = mkpolicy();
    assert!(sigsum::verify(checksum, spicy, signers, policy));
}

#[test]
fn test_verify_unknown_signer() {}

#[test]
fn test_verify_bad_leaf_signature() {}

#[test]
fn verify_unknown_log() {}

#[test]
fn verify_bad_log_signature() {}

#[test]
fn verify_not_enough_cosignatures() {}

#[test]
fn verify_bad_inclusion_proof() {}
