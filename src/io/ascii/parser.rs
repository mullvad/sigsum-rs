use std::error::Error;
use std::fmt;
use std::iter::Peekable;
use std::str::Lines;

use crate::{Hash, Signature};

#[derive(Debug)]
pub struct ParseAsciiError(pub(super) String);

impl fmt::Display for ParseAsciiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse error: {}", self.0)
    }
}

impl Error for ParseAsciiError {}

macro_rules! bail {
    ($msg:literal) => {
        return Err(ParseAsciiError(String::from($msg)))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(ParseAsciiError(format!($fmt, $($arg)*)))
    };
}

pub(crate) type Result<T> = std::result::Result<T, ParseAsciiError>;

pub(crate) struct Parser<'a> {
    lines: Peekable<Lines<'a>>,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(input: &'a str) -> Parser<'a> {
        Self {
            lines: input.lines().peekable(),
        }
    }

    pub(crate) fn parse<V: AsciiValue>(&mut self, field: &str) -> Result<V> {
        let Some(line) = self.lines.next() else {
            bail!("unexpected end of input");
        };
        let Some(value_str) = line.strip_prefix(&format!("{field}=")) else {
            bail!("expected field {}", field)
        };
        V::from_ascii(value_str)
    }

    pub(crate) fn at_end(&mut self) -> bool {
        self.lines.peek().is_none()
    }
}

pub(crate) trait AsciiValue: Sized {
    fn from_ascii(s: &str) -> Result<Self>;
}

impl AsciiValue for u64 {
    fn from_ascii(s: &str) -> Result<Self> {
        match s.parse() {
            Ok(s) => Ok(s),
            Err(err) => bail!("{}", err),
        }
    }
}

impl AsciiValue for Hash {
    fn from_ascii(s: &str) -> Result<Self> {
        let input = s.as_bytes();
        if input.len() != 64 {
            bail!("invalid hex length");
        }
        let mut bytes = [0; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = hexbyte(input, i)?;
        }
        Ok(Hash::from(bytes))
    }
}

impl AsciiValue for Signature {
    fn from_ascii(s: &str) -> Result<Self> {
        let input = s.as_bytes();
        if input.len() != 128 {
            bail!("invalid hex length");
        }
        let mut bytes = [0; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = hexbyte(input, i)?;
        }
        Ok(Self::from(bytes))
    }
}

impl<V0: AsciiValue, V1: AsciiValue> AsciiValue for (V0, V1) {
    fn from_ascii(s: &str) -> Result<Self> {
        let splits: Vec<&str> = s.split(' ').collect();
        if splits.len() != 2 {
            bail!("expected 2 values, found {}", splits.len())
        }
        Ok((V0::from_ascii(splits[0])?, V1::from_ascii(splits[1])?))
    }
}

impl<V0: AsciiValue, V1: AsciiValue, V2: AsciiValue> AsciiValue for (V0, V1, V2) {
    fn from_ascii(s: &str) -> Result<Self> {
        let splits: Vec<&str> = s.splitn(3, ' ').collect();
        if splits.len() != 3 {
            bail!("expected 3 values, found {}", splits.len())
        }
        Ok((
            V0::from_ascii(splits[0])?,
            V1::from_ascii(splits[1])?,
            V2::from_ascii(splits[2])?,
        ))
    }
}

// Extract the n-th byte from the input hex string (where n is the byte offset no the character
// offset).
fn hexbyte(input: &[u8], n: usize) -> Result<u8> {
    let pos = n * 2;
    // Get the most- and least-signigicant nibbles
    let msn = hexchar(input[pos])?;
    let lsn = hexchar(input[pos + 1])?;
    Ok((msn << 4) + lsn)
}

// Convert a single hex character into a u8.
fn hexchar(ch: u8) -> Result<u8> {
    match ch {
        b'0'..=b'9' => Ok(ch - 48),
        b'A'..=b'F' => Ok(ch - 55),
        b'a'..=b'f' => Ok(ch - 87),
        _ => bail!("invalid hex character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_at_end() {
        let mut p = Parser::new("foo=42\nbar=0\n");
        assert!(!p.at_end());
        let _ = p.parse::<u64>("foo");
        assert!(!p.at_end());
        let _ = p.parse::<u64>("bar");
        assert!(p.at_end());
    }

    #[test]
    fn parser_parse_u64() {
        let mut p = Parser::new("foo=42\n");
        assert_eq!(42, p.parse::<u64>("foo").unwrap());
        let mut p = Parser::new("foo=abc\n");
        assert_eq!(
            "parse error: invalid digit found in string",
            p.parse::<u64>("foo").unwrap_err().to_string()
        );
    }

    #[test]
    fn parser_parse_hash() {
        let mut p = Parser::new(
            "myhash=4242424242424242424242424242424242424242424242424242424242424242\n",
        );
        assert_eq!(Hash::from([0x42; 32]), p.parse("myhash").unwrap());

        // Bad character
        let mut p = Parser::new(
            "myhash=x242424242424242424242424242424242424242424242424242424242424242\n",
        );
        assert_eq!(
            "parse error: invalid hex character",
            p.parse::<Hash>("myhash").unwrap_err().to_string()
        );

        // Too short
        let mut p =
            Parser::new("myhash=424242424242424242424242424242424242424242424242424242424242424\n");
        assert_eq!(
            "parse error: invalid hex length",
            p.parse::<Hash>("myhash").unwrap_err().to_string()
        );

        // Too long
        let mut p = Parser::new(
            "myhash=424242424242424242424242424242424242424242424242424242424242424242\n",
        );
        assert_eq!(
            "parse error: invalid hex length",
            p.parse::<Hash>("myhash").unwrap_err().to_string()
        );
    }

    #[test]
    fn parser_parse_signature() {
        let mut p = Parser::new(
            "mysig=42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242\n");
        assert_eq!(
            Signature::from([0x42; 64]),
            p.parse::<Signature>("mysig").unwrap()
        );

        // Bad character
        let mut p = Parser::new(
            "mysig=x2424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242\n");
        assert_eq!(
            "parse error: invalid hex character",
            p.parse::<Signature>("mysig").unwrap_err().to_string()
        );

        // Too short
        let mut p = Parser::new(
            "mysig=424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242\n");
        assert_eq!(
            "parse error: invalid hex length",
            p.parse::<Signature>("mysig").unwrap_err().to_string()
        );

        // Too long
        let mut p = Parser::new(
            "mysig=4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242\n");
        assert_eq!(
            "parse error: invalid hex length",
            p.parse::<Signature>("mysig").unwrap_err().to_string()
        );
    }

    #[test]
    fn parser_parse_pair() {
        let mut p = Parser::new("mypair=42 123\n");
        assert_eq!((42, 123), p.parse::<(u64, u64)>("mypair").unwrap());
        let mut p = Parser::new("mypair=42 123 0\n");
        assert_eq!(
            "parse error: expected 2 values, found 3",
            p.parse::<(u64, u64)>("mypair").unwrap_err().to_string()
        );
    }

    #[test]
    fn parser_parse_tripple() {
        let mut p = Parser::new("mytripple=42 123 0\n");
        assert_eq!(
            (42, 123, 0),
            p.parse::<(u64, u64, u64)>("mytripple").unwrap()
        );
        let mut p = Parser::new("mytripple=42 123\n");
        assert_eq!(
            "parse error: expected 3 values, found 2",
            p.parse::<(u64, u64, u64)>("mytripple")
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn parser_parse_field_error() {
        let mut p = Parser::new("foo=42\n");
        assert_eq!(
            "parse error: expected field bar",
            p.parse::<u64>("bar").unwrap_err().to_string()
        );
        let mut p = Parser::new("");
        assert_eq!(
            "parse error: unexpected end of input",
            p.parse::<u64>("bar").unwrap_err().to_string()
        );
    }
}
