mod parser;

// This needs to be in scope to write!() to a String
use std::fmt::Write as _;

use crate::{
    Hash, InclusionProof, Protoleaf, Signature, SignedTreeHead, SigsumSignature, WitnessCosignature,
};
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

    #[allow(unused_must_use)]
    pub fn to_ascii(&self) -> String {
        let mut ascii = String::new();
        writeln!(ascii, "size={}", self.size);
        writeln!(ascii, "root_hash={:x}", self.root_hash);
        writeln!(ascii, "signature={:x}", self.signature);
        for cosig in self.cosignatures.iter() {
            writeln!(
                ascii,
                "cosignature={:x} {} {:x}",
                cosig.keyhash, cosig.timestamp, cosig.cosignature
            );
        }
        ascii
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

    #[allow(unused_must_use)]
    pub fn to_ascii(&self) -> String {
        let mut ascii = String::new();
        writeln!(ascii, "leaf_index={}", self.leaf_index);
        for h in self.node_hashes.iter() {
            writeln!(ascii, "node_hash={h:x}");
        }
        ascii
    }
}

impl Protoleaf {
    pub fn from_ascii(input: &str) -> Result<Self> {
        let mut p = Parser::new(input);
        let message = p.parse("message")?;
        let signature = p.parse("signature")?;
        let public_key = p.parse("public_key")?;
        Ok(Protoleaf {
            message,
            signature,
            public_key,
        })
    }

    #[allow(unused_must_use)]
    pub fn to_ascii(&self) -> String {
        let mut ascii = String::new();
        writeln!(ascii, "message={:x}", self.message);
        writeln!(ascii, "signature={:x}", self.signature);
        writeln!(ascii, "public_key={:x}", self.public_key);
        ascii
    }
}

impl SigsumSignature {
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

    #[allow(unused_must_use)]
    pub fn to_ascii(&self) -> String {
        let mut ascii = String::new();
        writeln!(ascii, "version=2");
        writeln!(ascii, "log={:x}", self.log_keyhash);
        writeln!(
            ascii,
            "leaf={:x} {:x}",
            self.leaf_keyhash, self.leaf_signature
        );
        writeln!(ascii);
        writeln!(ascii, "size={}", self.sth.size);
        writeln!(ascii, "root_hash={:x}", self.sth.root_hash);
        writeln!(ascii, "signature={:x}", self.sth.signature);
        for cosig in self.sth.cosignatures.iter() {
            writeln!(
                ascii,
                "cosignature={:x} {} {:x}",
                cosig.keyhash, cosig.timestamp, cosig.cosignature
            );
        }
        writeln!(ascii);
        writeln!(ascii, "leaf_index={}", self.proof.leaf_index);
        for h in self.proof.node_hashes.iter() {
            writeln!(ascii, "node_hash={h:x}");
        }
        ascii
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref PROTOLEAF: Protoleaf = Protoleaf {
            message: hex!("084c799cd551dd1d8d5c5f9a5d593b2e931f5e36122ee5c793c1d08a19839cc0").into(),
            signature: hex!("e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900").into(),
            public_key: hex!("16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245").into(),
        };
    }

    const PROTOLEAF_ASCII: &str = "\
    message=084c799cd551dd1d8d5c5f9a5d593b2e931f5e36122ee5c793c1d08a19839cc0\n\
    signature=e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900\n\
    public_key=16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245\n\
    ";

    #[test]
    fn protoleaf_from_ascii() {
        assert_eq!(*PROTOLEAF, Protoleaf::from_ascii(PROTOLEAF_ASCII).unwrap());
    }

    #[test]
    fn protoleaf_to_ascii() {
        assert_eq!(PROTOLEAF_ASCII, (*PROTOLEAF).to_ascii());
    }

    lazy_static!{
        static ref STH: SignedTreeHead = SignedTreeHead {
            size: 1285,
            root_hash: hex!("8100f29c0e9017a7512dab0911bf06a4b5b99cd77d8c710635307b5d217af1f6").into(),
            signature: hex!("e327fe13e5c3d2043cbf69fe1b778f77cb10a8e14fc09309dd375c9af25903f9ec35906cfb2c36ab2d210329eb538a6673487d2d101800370c978634b6f9f70d").into(),
            cosignatures: vec![
                WitnessCosignature {
                    keyhash: hex!("1a450ecf1f49a4e4580c35e4d83316a74deda949dbb7d338e89d4315764d88de").into(),
                    timestamp: 1687170591,
                    cosignature: hex!("cacc54d315609b796f72ac1d71d1bbc15667853ed980bd3e0f957de7a875b84bd2dcde6489fc3ed66428190ce588ac1061b0d5748e73cfb887ebf38d0b53060a").into(),
                },
                WitnessCosignature {
                    keyhash: hex!("73b6cbe5e3c8e679fb5967b78c59e95db2969a5c13b3423b5e69523e3d52f531").into(),
                    timestamp: 1687170591,
                    cosignature: hex!("7f568da17c57ea322a9c2668ae9fc2c1d6ab5556d9a997e7bfa1cbc4dc5cf7b94e0cead42d481bf0d3d90ad2ee0d272e9e687f8f82fddf76d37d722c6815fe0f").into(),
                },
            ],
        };
    }

    const STH_ASCII: &str = "\
    size=1285\n\
    root_hash=8100f29c0e9017a7512dab0911bf06a4b5b99cd77d8c710635307b5d217af1f6\n\
    signature=e327fe13e5c3d2043cbf69fe1b778f77cb10a8e14fc09309dd375c9af25903f9ec35906cfb2c36ab2d210329eb538a6673487d2d101800370c978634b6f9f70d\n\
    cosignature=1a450ecf1f49a4e4580c35e4d83316a74deda949dbb7d338e89d4315764d88de 1687170591 cacc54d315609b796f72ac1d71d1bbc15667853ed980bd3e0f957de7a875b84bd2dcde6489fc3ed66428190ce588ac1061b0d5748e73cfb887ebf38d0b53060a\n\
    cosignature=73b6cbe5e3c8e679fb5967b78c59e95db2969a5c13b3423b5e69523e3d52f531 1687170591 7f568da17c57ea322a9c2668ae9fc2c1d6ab5556d9a997e7bfa1cbc4dc5cf7b94e0cead42d481bf0d3d90ad2ee0d272e9e687f8f82fddf76d37d722c6815fe0f\n\
    ";

    #[test]
    fn sth_from_ascii() {
        assert_eq!(*STH, SignedTreeHead::from_ascii(STH_ASCII).unwrap());
    }

    #[test]
    fn sth_to_ascii() {
        assert_eq!(STH_ASCII, (*STH).to_ascii());
    }

    lazy_static! {
        static ref PROOF: InclusionProof = InclusionProof {
            leaf_index: 2,
            node_hashes: vec![
                hex!("35fd6eb70d46d60679775c346225688e6e84c02c3c7978e5c51daf8decc22d2f").into(),
                hex!("11a2b46fb34efed4abbd144f8666bda8b83ee2ee6f7685062ed5cd68d616412a").into(),
            ],
        };
    }

    const PROOF_ASCII: &str = "\
    leaf_index=2\n\
    node_hash=35fd6eb70d46d60679775c346225688e6e84c02c3c7978e5c51daf8decc22d2f\n\
    node_hash=11a2b46fb34efed4abbd144f8666bda8b83ee2ee6f7685062ed5cd68d616412a\n\
    ";

    #[test]
    fn proof_from_ascii() {
        assert_eq!(*PROOF, InclusionProof::from_ascii(PROOF_ASCII).unwrap());
    }

    #[test]
    fn proof_to_ascii() {
        assert_eq!(PROOF_ASCII, (*PROOF).to_ascii());
    }

    lazy_static! {
        static ref SSIG: SigsumSignature = SigsumSignature {
            log_keyhash: hex!("4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d")
                .into(),
            leaf_keyhash: hex!("16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245").into(),
            leaf_signature: hex!("e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900").into(),
            sth: (*STH).clone(),
            proof: (*PROOF).clone(),
        };
    }

    const SSIG_ASCII:&str = "\
    version=2\n\
    log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\n\
    leaf=16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245 e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900\n\
    \n\
    size=1285\n\
    root_hash=8100f29c0e9017a7512dab0911bf06a4b5b99cd77d8c710635307b5d217af1f6\n\
    signature=e327fe13e5c3d2043cbf69fe1b778f77cb10a8e14fc09309dd375c9af25903f9ec35906cfb2c36ab2d210329eb538a6673487d2d101800370c978634b6f9f70d\n\
    cosignature=1a450ecf1f49a4e4580c35e4d83316a74deda949dbb7d338e89d4315764d88de 1687170591 cacc54d315609b796f72ac1d71d1bbc15667853ed980bd3e0f957de7a875b84bd2dcde6489fc3ed66428190ce588ac1061b0d5748e73cfb887ebf38d0b53060a\n\
    cosignature=73b6cbe5e3c8e679fb5967b78c59e95db2969a5c13b3423b5e69523e3d52f531 1687170591 7f568da17c57ea322a9c2668ae9fc2c1d6ab5556d9a997e7bfa1cbc4dc5cf7b94e0cead42d481bf0d3d90ad2ee0d272e9e687f8f82fddf76d37d722c6815fe0f\n\
    \n\
    leaf_index=2\n\
    node_hash=35fd6eb70d46d60679775c346225688e6e84c02c3c7978e5c51daf8decc22d2f\n\
    node_hash=11a2b46fb34efed4abbd144f8666bda8b83ee2ee6f7685062ed5cd68d616412a\n\
    ";

    #[test]
    fn sigsumsig_from_ascii() {
        assert_eq!(*SSIG, SigsumSignature::from_ascii(SSIG_ASCII).unwrap());
    }

    #[test]
    fn sigsumsig_to_ascii() {
        assert_eq!(SSIG_ASCII, (*SSIG).to_ascii());
    }

    macro_rules! test_ssig_parse_error {
        ($testname:ident, $errormsg:literal, $input:literal) => {
            #[test]
            fn $testname() {
                assert_eq!(
                    $errormsg,
                    SigsumSignature::from_ascii($input).unwrap_err().to_string()
                );
            }
        };
    }

    test_ssig_parse_error! {
        ssig_missing_part,
        "expected 3 parts, got 2",
        "\
        version=2\n\
        log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\n\
        leaf=16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245 e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900\n\
        \n\
        size=4898\n\
        root_hash=5a2221ac3be281d2403abb44f9b6a8b1b1b2db97e5838d029a2df19db5e708bd\n\
        signature=67de0c13f8ae8a13ca2ad2aaab35326ba55186d240cbb48f4872a79847a41b5d2b43820dc8f4ae43030d432bbf753c365ba7a248fc12ea7be53f05bb72829409\n\
        "
    }

    test_ssig_parse_error! { sigsum_signature_too_many_parts,
        "expected 3 parts, got 4",
        "\
        version=2\n\
        log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\n\
        leaf=16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245 e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900\n\
        \n\
        size=1\n\
        root_hash=5a2221ac3be281d2403abb44f9b6a8b1b1b2db97e5838d029a2df19db5e708bd\n\
        signature=67de0c13f8ae8a13ca2ad2aaab35326ba55186d240cbb48f4872a79847a41b5d2b43820dc8f4ae43030d432bbf753c365ba7a248fc12ea7be53f05bb72829409\n\
        \n\
        leaf_index=1\n\
        \n\
        abc=123\n\
        "
    }

    test_ssig_parse_error! { sigsum_signature_version_not_supported,
        "version 666 not supported",
        "\
        version=666\n\
        log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\n\
        leaf=16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245 e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900\n\
        \n\
        size=1\n\
        root_hash=5a2221ac3be281d2403abb44f9b6a8b1b1b2db97e5838d029a2df19db5e708bd\n\
        signature=67de0c13f8ae8a13ca2ad2aaab35326ba55186d240cbb48f4872a79847a41b5d2b43820dc8f4ae43030d432bbf753c365ba7a248fc12ea7be53f05bb72829409\n\
        \n\
        leaf_index=1\n\
        "
    }

    test_ssig_parse_error! { sigsum_signature_extra_line,
        "expected an empty line after 'leaf'",
        "\
        version=2\n\
        log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d\n\
        leaf=16e8e5005d909e941b34d040b646dba5b6608e5e3353c7db860f9b8849eae245 e82c007b640da6375657e95bd9e3768017cd9b9478dffb7496a7de69b2e8608ceb35d336b44a3b1a3b0d4493cbc694bf87daf279684473024557dd427d34d900\n\
        abc=123\n\
        \n\
        size=1\n\
        root_hash=5a2221ac3be281d2403abb44f9b6a8b1b1b2db97e5838d029a2df19db5e708bd\n\
        signature=67de0c13f8ae8a13ca2ad2aaab35326ba55186d240cbb48f4872a79847a41b5d2b43820dc8f4ae43030d432bbf753c365ba7a248fc12ea7be53f05bb72829409\n\
        \n\
        leaf_index=1\n\
        "
    }
}
