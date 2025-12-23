use std::iter::Enumerate;
use std::str::Lines;

use super::{Policy, PolicyBuilder};
use crate::crypto::PublicKey;

#[derive(Debug, thiserror::Error)]
#[error("line {lineno}: {reason}")]
pub struct ParsePolicyError {
    lineno: usize,
    reason: String,
}

macro_rules! bail {
    ($lineno:expr, $($farg:tt)*) => {
        return Err(ParsePolicyError{lineno: $lineno, reason: format!($($farg)*)})
    };
}

type Result<T> = std::result::Result<T, ParsePolicyError>;

impl Policy {
    /// Parse a policy from its string representation according to the
    /// [sigsum-go spec](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md).
    pub fn parse(data: &str) -> Result<Policy> {
        parse_policy(data)
    }
}

fn parse_policy(data: &str) -> Result<Policy> {
    let mut builder = PolicyBuilder::new();
    let lines = PolicyLines::new(data);
    for (lineno, tokens) in lines {
        match tokens[..] {
            ["log", ..] => {
                let nargs = tokens.len() - 1;
                if !(1..=2).contains(&nargs) {
                    bail!(
                        lineno,
                        "invalid log rule: expected 1 or 2 arguments, got {nargs}"
                    );
                }
                let pubkey = parse_key(tokens[1], lineno)?;
                let url = tokens.get(2).map(|s| (*s).into());
                if let Err(err) = builder.add_log(pubkey, url) {
                    bail!(lineno, "invalid log rule: {err}")
                }
            }
            ["witness", ..] => {
                let nargs = tokens.len() - 1;
                if !(2..=3).contains(&nargs) {
                    bail!(
                        lineno,
                        "invalid witness rule: expected 2 or 3 arguments, got {nargs}"
                    );
                }
                let name = tokens[1];
                let pubkey = parse_key(tokens[2], lineno)?;
                let url = tokens.get(3).map(|s| (*s).into());
                if let Err(err) = builder.add_witness(name.into(), pubkey, url) {
                    bail!(lineno, "invalid witness rule: {err}")
                }
            }
            ["group", ..] => {
                let nargs = tokens.len() - 1;
                if nargs < 3 {
                    bail!(
                        lineno,
                        "invalid group rule: expected at least 3 arguments, got {nargs}"
                    );
                }
                let name = tokens[1];
                let k = tokens[2];
                let members: Vec<_> = tokens[3..].iter().map(|n| (*n).into()).collect();
                let Some(k) = parse_k(k, members.len()) else {
                    bail!(lineno, "invalid group rule: cannot parse {k} as an integer");
                };
                if let Err(err) = builder.add_group(name.into(), k, members) {
                    bail!(lineno, "invalid group rule: {err}");
                }
            }
            ["quorum", name] => {
                if name != "none" {
                    if let Err(err) = builder.set_quorum(name.into()) {
                        bail!(lineno, "invalid quorum rule: {err}");
                    }
                }
            }
            ["quorum", ..] => bail!(lineno, "invalid quorum rule: expected exactly one argument"),
            [unknown, ..] => bail!(lineno, "unknown keyword `{unknown}`"),
            [] => unreachable!("PolicyLines skips empty lines"),
        }
    }
    Ok(builder.build())
}

fn parse_k(k: &str, n: usize) -> Option<usize> {
    if k == "any" {
        Some(1)
    } else if k == "all" {
        Some(n)
    } else {
        k.parse().ok()
    }
}

fn parse_key(hex: &str, lineno: usize) -> Result<PublicKey> {
    if base16ct::decoded_len(hex.as_bytes()) != Ok(32) {
        return Err(ParsePolicyError {
            lineno,
            reason: String::from("invalid public key: wrong length"),
        });
    }
    let mut buf = [0; 32];
    match base16ct::mixed::decode(hex, &mut buf) {
        Err(_) => Err(ParsePolicyError {
            lineno,
            reason: "invalid public key: invalid hex encoding".to_string(),
        }),
        Ok(_) => Ok(buf.into()),
    }
}

// PolicyLines is essentially a lexer for parsing policy files.
//
// It implements a custom iterator that handles most low-level details of parsing policy files,
// splitting, numbering, filtering and tokenizing lines.
struct PolicyLines<'a>(Enumerate<Lines<'a>>);

impl<'a> PolicyLines<'a> {
    fn new(input: &'a str) -> Self {
        Self(input.lines().enumerate())
    }
}

impl<'a> Iterator for PolicyLines<'a> {
    // Return a pair line number + tokens
    type Item = (usize, Vec<&'a str>);

    // next() is the only required method
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (i, line) = self.0.next()?;
            let line = line.trim_ascii();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let tokens = line.split_ascii_whitespace().collect();
            return Some((i + 1, tokens));
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn policy_lines_empty() {
        let pls: Vec<(usize, Vec<&str>)> = PolicyLines::new("").collect();
        assert_eq!(pls, vec![]);
    }

    #[test]
    fn policy_lines() {
        let pls: Vec<(usize, Vec<&str>)> = PolicyLines::new(
            "# This is a comment\n\
             foo bar\n\
             \n\
             # The next line uses tabs\n\
             foo\tbar\n\
             \n\
             # This one mixes whitespaces\n\
             foo  \tbar\t  baz \t biz\n\
             \n\
             # Heading/trailing spaces\n\
             \t\n\
             \t  \n\
             \t# Indented comment\n\
             foo\t \n\
             \n\
             # Unicode space\n\
             foo\u{2003}bar\n\
             \u{2003}\n\
             ",
        )
        .collect();
        assert_eq!(
            pls,
            vec![
                (2, vec!["foo", "bar"]),
                (5, vec!["foo", "bar"]),
                (8, vec!["foo", "bar", "baz", "biz"]),
                (14, vec!["foo"]),
                (17, vec!["foo\u{2003}bar"]),
                (18, vec!["\u{2003}"]),
            ]
        );
    }

    #[test]
    fn parse_policy_empty() {
        let expected = PolicyBuilder::new().build();
        let actual = parse_policy("").unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_logs() {
        let expected = {
            let mut b = PolicyBuilder::new();
            b.add_log(
                hex!("fd07e34679d68f7042f0d2d3d21e956abdd0b56b1abc3d659b2b51f8e40a113e").into(),
                None,
            )
            .unwrap();
            b.add_log(
                hex!("348129817da7b3cbf1f87e0d82b65bc300869e4b65ba40f0f0c23588c5279d2b").into(),
                Some("http://example.com".into()),
            )
            .unwrap();
            b.build()
        };
        let actual =
            parse_policy("\
                log fd07e34679d68f7042f0d2d3d21e956abdd0b56b1abc3d659b2b51f8e40a113e\n\
                log 348129817da7b3cbf1f87e0d82b65bc300869e4b65ba40f0f0c23588c5279d2b http://example.com\n\
                quorum none
                ").unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_witnesses() {
        let expected = {
            let mut b = PolicyBuilder::new();
            b.add_witness(
                "WIT-1".into(),
                hex!("acf9f514e85ba44ebf00faf1bc36a16c42f2915c7b2728b489223fdcf3f2b6e3").into(),
                None,
            )
            .unwrap();
            b.add_witness(
                "WIT-2".into(),
                hex!("df329030f76b3616f1c50f3f8ae7ce6cf3fa92905ab7ce47bbc8be71226b65c9").into(),
                Some("http://example.com/witness".into()),
            )
            .unwrap();
            b.build()
        };
        let actual = parse_policy("\
                witness WIT-1 acf9f514e85ba44ebf00faf1bc36a16c42f2915c7b2728b489223fdcf3f2b6e3\n\
                witness WIT-2 df329030f76b3616f1c50f3f8ae7ce6cf3fa92905ab7ce47bbc8be71226b65c9 http://example.com/witness\n\
                quorum none\n\
                ").unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_group() {
        let expected = {
            let mut b = PolicyBuilder::new();
            b.add_witness(
                "WIT-1".into(),
                hex!("acf9f514e85ba44ebf00faf1bc36a16c42f2915c7b2728b489223fdcf3f2b6e3").into(),
                None,
            )
            .unwrap();
            b.add_witness(
                "WIT-2".into(),
                hex!("df329030f76b3616f1c50f3f8ae7ce6cf3fa92905ab7ce47bbc8be71226b65c9").into(),
                Some("http://example.com/witness".into()),
            )
            .unwrap();
            b.add_group("GRP".into(), 1, vec!["WIT-1".into(), "WIT-2".into()])
                .unwrap();
            b.set_quorum("GRP".into()).unwrap();
            b.build()
        };
        let actual = parse_policy("\
                witness WIT-1 acf9f514e85ba44ebf00faf1bc36a16c42f2915c7b2728b489223fdcf3f2b6e3\n\
                witness WIT-2 df329030f76b3616f1c50f3f8ae7ce6cf3fa92905ab7ce47bbc8be71226b65c9 http://example.com/witness\n\
                group GRP 1 WIT-1 WIT-2\n\
                quorum GRP\n\
                ").unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_policy_invalid_public_key() {
        insta::assert_snapshot!(
            parse_policy("log fd07e34679d68f7042f0d2d3d21e956abdd0b56b1abc3d659b2b51f8e40a11").unwrap_err(),
            @"line 1: invalid public key: wrong length",
        );
        insta::assert_snapshot!(
            parse_policy("log xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").unwrap_err(),
            @"line 1: invalid public key: invalid hex encoding",
        );
    }

    #[test]
    fn parse_policy_invalid_log_rule() {
        insta::assert_snapshot!(
            parse_policy("log").unwrap_err(),
            @"line 1: invalid log rule: expected 1 or 2 arguments, got 0",
        );
        insta::assert_snapshot!(
            parse_policy("log fd07e34679d68f7042f0d2d3d21e956abdd0b56b1abc3d659b2b51f8e40a113e https://log.io/ xxx").unwrap_err(),
            @"line 1: invalid log rule: expected 1 or 2 arguments, got 3",
        );
    }

    #[test]
    fn parse_policy_invalid_witness_rule() {
        insta::assert_snapshot!(
            parse_policy("witness foo").unwrap_err(),
            @"line 1: invalid witness rule: expected 2 or 3 arguments, got 1",
        );
        insta::assert_snapshot!(
            parse_policy("witness foo fd07e34679d68f7042f0d2d3d21e956abdd0b56b1abc3d659b2b51f8e40a113e https://log.io/ xxx").unwrap_err(),
            @"line 1: invalid witness rule: expected 2 or 3 arguments, got 4",
        );
    }

    #[test]
    fn parse_policy_invalid_group_rule() {
        insta::assert_snapshot!(
            parse_policy("group foo any").unwrap_err(),
            @"line 1: invalid group rule: expected at least 3 arguments, got 2",
        );
    }

    #[test]
    fn parse_policy_invalid_quorum_rule() {
        insta::assert_snapshot!(
            parse_policy("quorum").unwrap_err(),
            @"line 1: invalid quorum rule: expected exactly one argument",
        );
        insta::assert_snapshot!(
            parse_policy("quorum foo bar").unwrap_err(),
            @"line 1: invalid quorum rule: expected exactly one argument",
        );
        insta::assert_snapshot!(
            parse_policy("quorum foo").unwrap_err(),
            @"line 1: invalid quorum rule: foo: no sutch witness",
        );
    }

    #[test]
    fn parse_policy_multiple_quorum() {
        insta::assert_snapshot!(
            parse_policy("\
                witness WIT-1 acf9f514e85ba44ebf00faf1bc36a16c42f2915c7b2728b489223fdcf3f2b6e3\n\
                witness WIT-2 df329030f76b3616f1c50f3f8ae7ce6cf3fa92905ab7ce47bbc8be71226b65c9\n\
                quorum WIT-1\n\
                quorum WIT-2\n\
            ").unwrap_err(),
            @"line 4: invalid quorum rule: quorum already set",
        );
    }

    #[test]
    fn parse_policy_unknown_keyword() {
        insta::assert_snapshot!(parse_policy("foo bar").unwrap_err(), @"line 1: unknown keyword `foo`")
    }
}
