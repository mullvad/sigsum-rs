// We want to keep the code as close as possible as the spec. So we ignore clippy warningcs.
#![allow(clippy::all)]

use sha2::{Digest, Sha256};

type Hash = [u8; 32];

const LEAF_HASH_PREFIX: &[u8] = &[0x00];
const NODE_HASH_PREFIX: &[u8] = &[0x01];

/// https://www.rfc-editor.org/rfc/rfc9162.html#name-merkle-inclusion-proofs
pub fn verify_inclusion(
    leaf_hash: Hash,
    leaf_index: u64,
    tree_size: u64,
    root_hash: Hash,
    inclusion_path: Vec<Hash>,
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = leaf_hash;
    for p in inclusion_path.iter() {
        if sn == 0 {
            return false;
        }
        if lsb(fn_) || fn_ == sn {
            r = Sha256::new_with_prefix(NODE_HASH_PREFIX)
                .chain_update(p)
                .chain_update(r)
                .finalize()
                .into();
            if !lsb(fn_) {
                'inner: loop {
                    fn_ = fn_ >> 1;
                    sn = sn >> 1;
                    if lsb(fn_) || fn_ == 0 {
                        break 'inner;
                    }
                }
            }
        } else {
            r = Sha256::new_with_prefix(NODE_HASH_PREFIX)
                .chain_update(r)
                .chain_update(p)
                .finalize()
                .into();
        }
        fn_ = fn_ >> 1;
        sn = sn >> 1;
    }
    return sn == 0 && r == root_hash;
}

// return true if the least significant bit of n is set
pub fn lsb(n: u64) -> bool {
    n & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64ct::{Base64, Encoding};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct CctvCase {
        leaf_hash: String,
        leaf_index: u64,
        tree_size: u64,
        root_hash: String,
        inclusion_path: Vec<String>,
    }

    fn b64hash(s: &str) -> Hash {
        Base64::decode_vec(s)
            .expect("valid base 64")
            .try_into()
            .expect("valid hash")
    }

    #[test]
    fn inclusion_valid() {
        let data: Vec<CctvCase> =
            serde_json::from_str(include_str!("testdata/inclusion-valid.json"))
                .expect("should be valid json");
        for (idx, t) in data.iter().enumerate() {
            let leaf_hash = b64hash(&t.leaf_hash);
            let root_hash = b64hash(&t.root_hash);
            let inclusion_path = t.inclusion_path.iter().map(|s| b64hash(&s)).collect();
            assert!(
                verify_inclusion(
                    leaf_hash,
                    t.leaf_index,
                    t.tree_size,
                    root_hash,
                    inclusion_path
                ),
                "inclusion proof verification failed on test case inclusion-valid.json#/{}",
                idx
            );
        }
    }

    #[test]
    fn inclusion_invalid() {
        let data: Vec<CctvCase> =
            serde_json::from_str(include_str!("testdata/inclusion-invalid.json"))
                .expect("should be valid json");
        for (idx, t) in data.iter().enumerate() {
            let leaf_hash = b64hash(&t.leaf_hash);
            let root_hash = b64hash(&t.root_hash);
            let inclusion_path = t.inclusion_path.iter().map(|s| b64hash(&s)).collect();
            assert!(
                !verify_inclusion(
                    leaf_hash,
                    t.leaf_index,
                    t.tree_size,
                    root_hash,
                    inclusion_path
                ),
                "inclusion proof verification succeeded on test case inclusion-invalid.json#/{}",
                idx
            );
        }
    }
}

// Compute leaf hashs as defined in the RFC
pub fn leaf_hash(leaf: impl AsRef<[u8]>) -> Hash {
    Sha256::new_with_prefix(LEAF_HASH_PREFIX)
        .chain_update(leaf)
        .finalize()
        .into()
}
