use crate::{Hash, InclusionProof, Signature, SignedTreeHead};

/// An offline-verifiable, transparency-logged signature.
///
/// This is a structure that bundles:
/// - a keyhash identifying a Sigsum log
/// - an Ed25519 signature of some data
/// - a keyhash identifying the signer of the data
/// - a signed tree head from the Sigsum log
/// - a proof that the signature is included in the tree
#[derive(Debug, PartialEq)]
pub struct SigsumSignature {
    pub(crate) log_keyhash: Hash,
    pub(crate) leaf_keyhash: Hash,
    pub(crate) leaf_signature: Signature,
    pub(crate) sth: SignedTreeHead,
    pub(crate) proof: InclusionProof,
}
