// Implements types related to the sigsum log

use crate::crypto::{Hash, PublicKey, Signature};

/// A signed tree head, as returned by the get-tree-head endpoint.
#[derive(Debug, Clone, PartialEq)]
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

/// An inclusion proof, as returned by the get-inclusion-proof endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub node_hashes: Vec<Hash>,
}

/// A protoleaf, which is the data submitted to the add-leaf endpoint of a Sigsum log.
#[derive(Debug, Clone, PartialEq)]
pub struct Protoleaf {
    pub message: Hash,
    pub signature: Signature,
    pub public_key: PublicKey,
}

/// A tree leaf, as stored in a sigsum log.
#[derive(Debug, Clone, PartialEq)]
pub struct Leaf {
    pub digest: Hash,
    pub signature: Signature,
    pub keyhash: Hash,
}
