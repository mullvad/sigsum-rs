use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use base64ct::{Base64, Encoding};

use crate::merkle;
use crate::{Hash, PublicKey, Signature, SignedTreeHead, SigsumSignature};

#[derive(Debug)]
pub struct VerifyError(pub(super) String);

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "verify error: {}", self.0)
    }
}

impl Error for VerifyError {}

type Result = std::result::Result<(), VerifyError>;

macro_rules! bail {
    ($msg:literal) => {
        return Err(VerifyError(String::from($msg)))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(VerifyError(format!($fmt, $($arg)*)))
    };
}

// A K-of-n policy
// TODO: Support the full quorum logic
/// A Sigsum policy.
///
/// The Sigsum policy dictates if a signed tree head is considered valid (and by extension, if a
/// Sigsum signature is valid).
#[derive(Debug)]
pub struct Policy {
    logs: Vec<PublicKey>,
    witnesses: Vec<PublicKey>,
    quorum: usize,
}

impl Policy {
    pub fn new_k_of_n(logs: Vec<PublicKey>, witnesses: Vec<PublicKey>, k: usize) -> Self {
        Self {
            logs,
            witnesses,
            quorum: k,
        }
    }
}

///  Verify that `signature` is a good signature for `message` from one of the `signers`, logged
///  according to `policy`.
pub fn verify(
    message: &Hash,
    signature: SigsumSignature,
    signers: Vec<PublicKey>,
    policy: &Policy,
) -> Result {
    let checksum = Hash::new(message);
    verify_leaf(
        &checksum,
        &signature.leaf_signature,
        &signature.leaf_keyhash,
        signers,
    )?;
    verify_sth(&signature.log_keyhash, &signature.sth, policy)?;
    verify_inclusion_proof(&checksum, &signature)?;
    Ok(())
}

fn verify_leaf(
    checksum: &Hash,
    signature: &Signature,
    keyhash: &Hash,
    signers: Vec<PublicKey>,
) -> Result {
    for key in signers.iter() {
        if Hash::new(key) == *keyhash {
            let signed = [b"sigsum.org/v1/tree-leaf\x00".as_slice(), checksum.as_ref()].concat();
            signed.len();
            if key.verify_signature(&signed, signature) {
                return Ok(());
            } else {
                bail!("bad leaf signature");
            }
        }
    }
    bail!("unknown leaf keyhash")
}

fn verify_sth(log_keyhash: &Hash, sth: &SignedTreeHead, policy: &Policy) -> Result {
    let Some(log_key) = policy.logs.iter().find(|k| Hash::new(k) == *log_keyhash) else {
        bail!("unknown log keyhash");
    };
    let msg = serialize_tree_head(&Hash::new(log_key), sth.size, &sth.root_hash);
    if !log_key.verify_signature(msg.as_bytes(), &sth.signature) {
        bail!("bad log signature");
    }
    let mut valid_cosignatures = 0;
    for cosig in sth.cosignatures.iter() {
        let Some(witness_key) = policy
            .witnesses
            .iter()
            .find(|k| Hash::new(k) == cosig.keyhash)
        else {
            // We don't know about this witness, that's ok and we just move on.
            continue;
        };
        let msg = serialize_cosigned_checkpoint(
            cosig.timestamp,
            &Hash::new(log_key),
            sth.size,
            &sth.root_hash,
        );
        if !witness_key.verify_signature(msg.as_bytes(), &cosig.cosignature) {
            bail!("bad witness cosignature from {:x}", witness_key)
        }
        valid_cosignatures += 1;
    }
    if valid_cosignatures >= policy.quorum {
        Ok(())
    } else {
        bail!("not enough valid cosignatures");
    }
}

fn is_quorum(verified: &HashSet<Hash>, policy: &Policy, name: &str) -> bool {
    todo!()
}

// Serialized tree head used for signing
// => https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md#222--merkle-tree-head
fn serialize_tree_head(log_keyhash: &Hash, log_size: u64, root_hash: &Hash) -> String {
    format!(
        "sigsum.org/v1/tree/{:x}\n{}\n{}\n",
        log_keyhash,
        log_size,
        Base64::encode_string(root_hash.as_ref())
    )
}

fn serialize_cosigned_checkpoint(
    time: u64,
    log_keyhash: &Hash,
    log_size: u64,
    root_hash: &Hash,
) -> String {
    format!(
        "cosignature/v1\ntime {}\n{}",
        time,
        serialize_tree_head(log_keyhash, log_size, root_hash)
    )
}

fn verify_inclusion_proof(checksum: &Hash, signature: &SigsumSignature) -> Result {
    let leaf: Vec<u8> = [
        checksum.as_ref(),
        signature.leaf_signature.as_ref(),
        signature.leaf_keyhash.as_ref(),
    ]
    .concat();
    let leaf_hash = merkle::leaf_hash(leaf);
    if merkle::verify_inclusion(
        leaf_hash,
        signature.proof.leaf_index,
        signature.sth.size,
        signature.sth.root_hash.clone().into(),
        signature
            .proof
            .node_hashes
            .iter()
            .cloned()
            .map(|h| h.into())
            .collect(),
    ) {
        Ok(())
    } else {
        bail!("bad inclusion proof");
    }
}
