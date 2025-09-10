mod parser;

use crate::{Hash, InclusionProof, Signature, SignedTreeHead, SpicySignature, WitnessCosignature};
pub use parser::ParseAsciiError;
use parser::{Parser, Result};

impl SignedTreeHead {
    pub fn from_ascii(input: &str) -> Result<Self> {
        let mut p = Parser::new(input);
        let size: u64 = p.parse("size")?;
        let root_hash: Hash = p.parse("root_hash")?;
        let signature: Signature = p.parse("signature")?;
        let mut cosignatures = Vec::new();
        while !p.at_end() {
            let (keyhash, timestamp, cosignature): (Hash, u64, Signature) =
                p.parse("cosignature")?;
            cosignatures.push(WitnessCosignature {
                keyhash,
                timestamp,
                cosignature,
            });
        }
        Ok(SignedTreeHead {
            size,
            root_hash,
            signature,
            cosignatures,
        })
    }
}

impl InclusionProof {
    pub fn from_ascii(input: &str) -> Result<Self> {
        let mut p = Parser::new(input);
        let leaf_index = p.parse("leaf_index")?;
        let mut node_hashes = Vec::new();
        while !p.at_end() {
            let hash = p.parse("node_hash")?;
            node_hashes.push(hash);
        }
        Ok(Self {
            leaf_index,
            node_hashes,
        })
    }
}

impl SpicySignature {
    pub fn from_ascii(input: &str) -> Result<Self> {
        let parts: Vec<&str> = input.split("\n\n").collect();
        if parts.len() != 3 {
            return Err(ParseAsciiError(format!(
                "expected 3 parts, got {}",
                parts.len()
            )));
        }
        let mut p = Parser::new(parts[0]);
        let version: u64 = p.parse("version")?;
        if version != 2 {
            return Err(ParseAsciiError(format!("version {version} not supported")));
        }
        let log_keyhash = p.parse("log")?;
        let (leaf_keyhash, leaf_signature) = p.parse("leaf")?;
        if !p.at_end() {
            return Err(ParseAsciiError(
                "expected an empty line after 'leaf'".into(),
            ));
        }
        let sth = SignedTreeHead::from_ascii(parts[1])?;
        let proof = InclusionProof::from_ascii(parts[2])?;
        Ok(Self {
            log_keyhash,
            leaf_keyhash,
            leaf_signature,
            sth,
            proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sth_from_ascii() {
        insta::assert_debug_snapshot!(SignedTreeHead::from_ascii(include_str!(
            "testdata/tree-head.ascii"
        ))
        .unwrap());
    }

    #[test]
    fn inclusionproof_from_ascii() {
        insta::assert_debug_snapshot!(InclusionProof::from_ascii(include_str!(
            "testdata/inclusion-proof.ascii"
        ))
        .unwrap());
    }

    #[test]
    fn spicysig_from_ascii() {
        insta::assert_debug_snapshot!(SpicySignature::from_ascii(include_str!(
            "testdata/spicy-signature.ascii"
        ))
        .unwrap());
    }

    macro_rules! test_parse_error {
        ($testname:ident, $file:literal, $errormsg:literal) => {
            #[test]
            fn $testname() {
                let input = include_str!($file);
                assert_eq!(
                    $errormsg,
                    SpicySignature::from_ascii(input).unwrap_err().to_string()
                );
            }
        };
    }

    test_parse_error!(
        spicy_signature_missing_part,
        "testdata/spicy-signature_missing-part.ascii",
        "parse error: expected 3 parts, got 2"
    );
    test_parse_error!(
        spicy_signature_too_many_parts,
        "testdata/spicy-signature_too-many-parts.ascii",
        "parse error: expected 3 parts, got 4"
    );
    test_parse_error!(
        spicy_signature_version_not_supported,
        "testdata/spicy-signature_version-not-supported.ascii",
        "parse error: version 666 not supported"
    );
    test_parse_error!(
        spicy_signature_extra_line,
        "testdata/spicy-signature_extra-line.ascii",
        "parse error: expected an empty line after 'leaf'"
    );
}
