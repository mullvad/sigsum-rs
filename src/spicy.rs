use crate::{Hash, InclusionProof, Signature, SignedTreeHead};

#[derive(Debug, PartialEq)]
pub struct SpicySignature {
    pub(crate) log_keyhash: Hash,
    pub(crate) leaf_keyhash: Hash,
    pub(crate) leaf_signature: Signature,
    pub(crate) sth: SignedTreeHead,
    pub(crate) proof: InclusionProof,
}
