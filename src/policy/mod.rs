use std::collections::HashMap;

use crate::crypto::{Hash, PublicKey};

mod builtin;
mod parsing;

pub use parsing::ParsePolicyError;

/// A Sigsum policy.
///
/// The Sigsum policy dictates if a signed tree head is considered valid (and by extension, if a
/// Sigsum signature is valid).
#[derive(Debug, Eq, PartialEq)]
pub struct Policy {
    // logs keeps the list of log keys and URLs indexed by keyhash.
    logs: HashMap<Hash, Entity>,

    // witnesses keeps the list of witness keys and URLs indexed by keyhash.
    witnesses: HashMap<Hash, Entity>,

    // quorums keeps the quorum entries (witnesses and groups), indexed by name.
    quorums: HashMap<String, Quorum>,

    // quorum is the quorum required by the policy. Invariant: if present, quorum must be an
    // existing key in quorums.
    quorum: Option<String>,
}

#[derive(Debug)]
pub struct Log {
    pub pubkey: PublicKey,
    pub url: Option<String>,
}

#[derive(Debug)]
pub struct Witness {
    pub name: String,
    pub pubkey: PublicKey,
    pub url: Option<String>,
}

pub struct Logs<'a> {
    inner: std::collections::hash_map::Iter<'a, Hash, Entity>,
}

impl<'a> Iterator for Logs<'a> {
    type Item = Log;

    fn next(&mut self) -> Option<Self::Item> {
        let (_, entity) = self.inner.next()?;
        Some(Log {
            pubkey: entity.0.clone(),
            url: entity.1.clone(),
        })
    }
}

impl Policy {
    pub fn logs(&self) -> Logs<'_> {
        Logs {
            inner: self.logs.iter(),
        }
    }

    pub fn get_witness_by_keyhash(&self, keyhash: &Hash) -> Option<Witness> {
        let entity = self.witnesses.get(keyhash)?;
        let name = self
            .quorums
            .iter()
            .filter_map(|(n, q)| match q {
                Quorum::Witness(h) if h == keyhash => Some(n),
                _ => None,
            })
            .next()
            .unwrap();
        Some(Witness {
            name: name.clone(),
            pubkey: entity.0.clone(),
            url: entity.1.clone(),
        })
    }
}

// Quorum is an internal enum that represent possible quorum values, i.e. witnesses and groups.
#[derive(Debug, Eq, PartialEq)]
enum Quorum {
    // A single witness, identified by its keyhash.
    // Invariant: if Witness(h) is in Policy.quorums, then h must be in Policy.witnesses.
    Witness(Hash),

    // A Group that requires at least k of its subquorums to pass.
    // Invariant: k <= length(members)
    // Invariant: if a group is in Policy.quorums, then all its members must be in
    // Policy.quorums as well.
    Group { k: usize, members: Vec<String> },
}

// Entity is a struct that is used internally to keep track of log/witness keys and URLs.
#[derive(Debug, Eq, PartialEq)]
struct Entity(PublicKey, Option<String>);

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum PolicyError {
    #[error("duplicate log key: {0:x}")]
    DuplicateLogKey(PublicKey),

    #[error("duplicate witness")]
    DuplicateWitnessKey(PublicKey),

    #[error("duplicate name")]
    DuplicateName(String),

    #[error("{0}: no sutch witness")]
    UnknownName(String),

    #[error("quorum already set")]
    QuorumAlreadySet,
}

pub struct PolicyBuilder(Policy);

impl Default for PolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyBuilder {
    pub fn new() -> Self {
        Self(Policy {
            logs: HashMap::new(),
            witnesses: HashMap::new(),
            quorums: HashMap::new(),
            quorum: None,
        })
    }
    pub fn add_log(&mut self, key: PublicKey, url: Option<String>) -> Result<(), PolicyError> {
        let keyhash = Hash::new(&key);
        if self.0.logs.contains_key(&keyhash) {
            return Err(PolicyError::DuplicateLogKey(key));
        }
        self.0.logs.insert(keyhash, Entity(key, url));
        Ok(())
    }

    pub fn add_witness(
        &mut self,
        name: String,
        key: PublicKey,
        url: Option<String>,
    ) -> Result<(), PolicyError> {
        let keyhash = Hash::new(&key);
        if self.0.witnesses.contains_key(&keyhash) {
            return Err(PolicyError::DuplicateWitnessKey(key));
        }
        if self.0.quorums.contains_key(&name) {
            return Err(PolicyError::DuplicateName(name));
        }
        self.0.witnesses.insert(keyhash.clone(), Entity(key, url));
        self.0.quorums.insert(name, Quorum::Witness(keyhash));
        Ok(())
    }

    pub fn add_group(
        &mut self,
        name: String,
        k: usize,
        members: Vec<String>,
    ) -> Result<(), PolicyError> {
        if self.0.quorums.contains_key(&name) {
            return Err(PolicyError::DuplicateName(name));
        }
        for name in members.iter() {
            if !self.0.quorums.contains_key(name) {
                return Err(PolicyError::UnknownName(name.into()));
            }
        }
        self.0.quorums.insert(name, Quorum::Group { k, members });
        Ok(())
    }

    pub fn set_quorum(&mut self, name: String) -> Result<(), PolicyError> {
        if self.0.quorum.is_some() {
            return Err(PolicyError::QuorumAlreadySet);
        }
        if !self.0.quorums.contains_key(&name) {
            return Err(PolicyError::UnknownName(name));
        }
        self.0.quorum = Some(name);
        Ok(())
    }

    pub fn build(self) -> Policy {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn build_empty_policy() {
        let builder = PolicyBuilder::new();
        let expected = Policy {
            logs: HashMap::new(),
            witnesses: HashMap::new(),
            quorums: HashMap::new(),
            quorum: None,
        };
        assert_eq!(expected, builder.build());
    }

    #[test]
    fn build_policy() {
        let mut builder = PolicyBuilder::new();
        builder
            .add_log(
                hex!("ec5681da2b676ab81df2daea3254cd8c4a5149318a62ae3bec6b4e80504b3b24").into(),
                Some(String::from("https://log.example.org")),
            )
            .unwrap();
        builder
            .add_log(
                hex!("7808644343ae328487d1a9f226c2448af70c9517580217f5a4872f28ee7b94e2").into(),
                None,
            )
            .unwrap();
        builder
            .add_witness(
                String::from("witness01"),
                hex!("eb091ebb478efd464c38eaeccd0c20591d187cd461fb71bc0c1077acd2a6dc48").into(),
                Some(String::from("https://witness.example.org")),
            )
            .unwrap();
        builder
            .add_witness(
                String::from("witness02"),
                hex!("1f79dd39c4f08fa50236836aa931ab673476a6426eaec3c5927ca92f7c99d0d6").into(),
                None,
            )
            .unwrap();
        builder
            .add_group(
                String::from("mygroup"),
                2,
                vec![String::from("witness01"), String::from("witness02")],
            )
            .unwrap();
        builder.set_quorum(String::from("mygroup")).unwrap();
        let expected = Policy {
            logs: HashMap::from([
                (
                    hex!("e919506c3a798f2030f14046e39f03773c12b390e1010c95d2256d0ae594354e").into(),
                    Entity(
                        hex!("7808644343ae328487d1a9f226c2448af70c9517580217f5a4872f28ee7b94e2")
                            .into(),
                        None,
                    ),
                ),
                (
                    hex!("d05a4bb520e4699e424b0f7f891746bd176fd0d581a5fdc55cb5c2cb57e3adf2").into(),
                    Entity(
                        hex!("ec5681da2b676ab81df2daea3254cd8c4a5149318a62ae3bec6b4e80504b3b24")
                            .into(),
                        Some("https://log.example.org".into()),
                    ),
                ),
            ]),
            witnesses: HashMap::from([
                (
                    hex!("d9440882ae2bd57076d4da2e7a12d4b26e137d56116419a69f8d6969709ed747").into(),
                    Entity(
                        hex!("1f79dd39c4f08fa50236836aa931ab673476a6426eaec3c5927ca92f7c99d0d6")
                            .into(),
                        None,
                    ),
                ),
                (
                    hex!("76d1d63740b74b4bb06f0d8c3a5eab35e07481b53df4c086eb3ae6f04f3922aa").into(),
                    Entity(
                        hex!("eb091ebb478efd464c38eaeccd0c20591d187cd461fb71bc0c1077acd2a6dc48")
                            .into(),
                        Some("https://witness.example.org".into()),
                    ),
                ),
            ]),
            quorums: HashMap::from([
                (
                    "witness01".into(),
                    Quorum::Witness(
                        hex!("76d1d63740b74b4bb06f0d8c3a5eab35e07481b53df4c086eb3ae6f04f3922aa")
                            .into(),
                    ),
                ),
                (
                    "witness02".into(),
                    Quorum::Witness(
                        hex!("d9440882ae2bd57076d4da2e7a12d4b26e137d56116419a69f8d6969709ed747")
                            .into(),
                    ),
                ),
                (
                    "mygroup".into(),
                    Quorum::Group {
                        k: 2,
                        members: vec!["witness01".into(), "witness02".into()],
                    },
                ),
            ]),
            quorum: Some("mygroup".into()),
        };
        assert_eq!(expected, builder.build());
    }

    #[test]
    fn duplicate_log_key() {
        let key: PublicKey =
            hex!("ec5681da2b676ab81df2daea3254cd8c4a5149318a62ae3bec6b4e80504b3b24").into();
        let mut builder = PolicyBuilder::new();
        builder.add_log(key.clone(), None).unwrap();
        let res = builder.add_log(key.clone(), Some("https://example.org".into()));
        assert_eq!(Err(PolicyError::DuplicateLogKey(key)), res);
        insta::assert_debug_snapshot!(builder.build());
    }

    #[test]
    fn duplicate_witness_key() {
        let key: PublicKey =
            hex!("ec5681da2b676ab81df2daea3254cd8c4a5149318a62ae3bec6b4e80504b3b24").into();
        let mut builder = PolicyBuilder::new();
        builder
            .add_witness("mywitness1".into(), key.clone(), None)
            .unwrap();
        let res = builder.add_witness(
            "mywitness2".into(),
            key.clone(),
            Some("https://example.com".into()),
        );
        assert_eq!(Err(PolicyError::DuplicateWitnessKey(key)), res);
        insta::assert_debug_snapshot!(builder.build());
    }

    #[test]
    fn duplicate_quorum_name() {
        let key1: PublicKey =
            hex!("ec5681da2b676ab81df2daea3254cd8c4a5149318a62ae3bec6b4e80504b3b24").into();
        let key2: PublicKey =
            hex!("d9440882ae2bd57076d4da2e7a12d4b26e137d56116419a69f8d6969709ed747").into();
        let name: String = "foo".into();
        let mut builder = PolicyBuilder::new();
        builder.add_witness(name.clone(), key1, None).unwrap();

        let res1 = builder.add_group(name.clone(), 1, vec!["foo".into()]);
        assert_eq!(Err(PolicyError::DuplicateName(name.clone())), res1);

        let res2 = builder.add_witness(name.clone(), key2, None);
        assert_eq!(Err(PolicyError::DuplicateName(name)), res2);

        insta::assert_debug_snapshot!(builder.build());
    }

    #[test]
    fn uplicate_unknown_member_name() {
        let mut builder = PolicyBuilder::new();
        let res = builder.add_group("mygroup".into(), 1, vec!["mywitness".into()]);
        assert_eq!(Err(PolicyError::UnknownName("mywitness".into())), res);
        insta::assert_debug_snapshot!(builder.build());
    }

    #[test]
    fn unknown_quorum_name() {
        let mut builder = PolicyBuilder::new();
        let res = builder.set_quorum("mywitness".into());
        assert_eq!(Err(PolicyError::UnknownName("mywitness".into())), res);
        insta::assert_debug_snapshot!(builder.build());
    }

    #[test]
    fn quorum_set_twice() {
        let key1: PublicKey =
            hex!("ec5681da2b676ab81df2daea3254cd8c4a5149318a62ae3bec6b4e80504b3b24").into();
        let key2: PublicKey =
            hex!("d9440882ae2bd57076d4da2e7a12d4b26e137d56116419a69f8d6969709ed747").into();
        let mut builder = PolicyBuilder::new();
        builder
            .add_witness("mywitness1".into(), key1, None)
            .unwrap();
        builder
            .add_witness("mywitness2".into(), key2, None)
            .unwrap();
        builder.set_quorum("mywitness1".into()).unwrap();
        let res = builder.set_quorum("mywitness2".into());
        assert_eq!(Err(PolicyError::QuorumAlreadySet), res);
        assert_eq!(Some("mywitness1".into()), builder.build().quorum);
    }
}
