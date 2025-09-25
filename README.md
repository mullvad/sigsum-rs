# sigsum-rs

sigsum-rs is a Rust implementation of the Sigsum library. It currently only supports offline verification but aims to eventually include submitting and monitoring.

## Installation

Add sigsum to your Rust project with [cargo](https://doc.rust-lang.org/cargo/).

```bash
cargo add sigsum
```

## Usage

```rust
use sigsum::{SigsumPolicy, SigsumSignature, Ed25519PublicKey};

let data = // some data;
let policy = SigsumPolicy::parse(policy_str);
let signature = SigsumSignature::from_ascii(ascii_signature);
let signers: Vec<Ed25519PublicKey> = ...;
assert!(verify_sigsum_signature(data, signature, signers, policy).is_ok());
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)??