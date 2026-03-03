use base64ct::{Base64, Encoding};

use crate::Hash;

// Serialized tree head used for signing
// => https://git.glasklar.is/sigsum/project/documentation/-/blob/main/log.md#222--merkle-tree-head
pub(crate) fn merkle_tree_head(log_keyhash: &Hash, log_size: u64, root_hash: &Hash) -> String {
    format!(
        "sigsum.org/v1/tree/{:x}\n{}\n{}\n",
        log_keyhash,
        log_size,
        Base64::encode_string(root_hash.as_ref())
    )
}

pub(crate) fn cosigned_checkpoint(
    time: u64,
    log_keyhash: &Hash,
    log_size: u64,
    root_hash: &Hash,
) -> String {
    format!(
        "cosignature/v1\ntime {}\n{}",
        time,
        merkle_tree_head(log_keyhash, log_size, root_hash)
    )
}
