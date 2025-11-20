// Implements types related to the sigsum log

use crate::crypto::{Hash, PublicKey, Signature};

#[derive(Debug, Clone, PartialEq)]
/// A signed tree head, as returned by the get-tree-head endpoint.
pub struct SignedTreeHead {
    pub size: u64,
    pub root_hash: Hash,
    pub signature: Signature,
    pub cosignatures: Vec<WitnessCosignature>,
}

/// A witness cosignature.
#[derive(Debug, Clone, PartialEq)]
pub struct WitnessCosignature {
    pub keyhash: Hash,
    pub timestamp: u64,
    pub cosignature: Signature,
}

#[derive(Debug, Clone, PartialEq)]
/// An inclusion proof, as returned by the get-inclusion-proof endpoint.
pub struct InclusionProof {
    pub leaf_index: u64,
    pub node_hashes: Vec<Hash>,
}

#[derive(Debug, Clone, PartialEq)]
/// A protoleaf, which is the data submitted to the add-leaf endpoint of a Sigsum log.
pub struct Protoleaf {
    pub message: Hash,
    pub signature: Signature,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq)]
/// A tree leaf, as stored in a sigsum log.
pub struct Leaf {
    pub digest: Hash,
    pub signature: Signature,
    pub keyhash: Hash,
}
