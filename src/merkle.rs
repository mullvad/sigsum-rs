use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];
pub type Signature = [u8; 64];

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
            r = Sha256::new_with_prefix([0x01])
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
            r = Sha256::new_with_prefix([0x01])
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

    use base64::engine::general_purpose::STANDARD;
    use base64::engine::Engine;
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
        STANDARD
            .decode(s)
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
