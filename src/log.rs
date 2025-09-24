// Implements types related to the sigsum log

use crate::crypto::{Hash, Signature};

#[derive(Debug, PartialEq)]
/// A signed tree head, as returned by the get-tree-head endpoint.
pub struct SignedTreeHead {
    pub size: u64,
    pub root_hash: Hash,
    pub signature: Signature,
    pub cosignatures: Vec<WitnessCosignature>,
}

/// A witness cosignature.
#[derive(Debug, PartialEq)]
pub struct WitnessCosignature {
    pub keyhash: Hash,
    pub timestamp: u64,
    pub cosignature: Signature,
}

#[derive(Debug, PartialEq)]
/// An inclusion proof, as returned by the get-inclusion-proof endpoint.
pub struct InclusionProof {
    pub leaf_index: u64,
    pub node_hashes: Vec<Hash>,
}
