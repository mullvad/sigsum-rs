# sigsum

sigsum-rs is a Rust implementation of the Sigsum library. It currently only
supports offline verification of sigsum signatures but aims to eventually
include submitting and monitoring.

## Installation

Add sigsum to your Rust project with [cargo](https://doc.rust-lang.org/cargo/).

```bash
cargo add sigsum
```

## Usage

```rust
use sigsum::{verify, Hash, Policy, PublicKey, SigsumSignature};
use hex_literal::hex;

let data = b"Hello, Sigsum!";
let signers: Vec<PublicKey> =
    vec![hex!("8a9b8b9f45a826b541c1477861a458c7b30ef1cc9600c515d593c4e2f72f375e").into()];
let policy = Policy::new_k_of_n(
    vec![hex!("4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6").into()],
    vec![hex!("4a921b7caef58ae670cdc11ef4184f1c058f7b9259a9107a969f69fa54aa496f").into()],
    1,
);
let signature = SigsumSignature::from_ascii("version=2
log=4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
leaf=2ca612aaa355c19a0cc7ebaacb04723b97e873df4dbadd0f97a2e00a13d8f76a 1a5fcc2b05fb6ca66dbc7e62bcc7934fb0ebf49bba501c285222550a67e590fa3237b338ba59d2327800788b85ff9e80ea88c71157519974c70d10c825e65401

size=8858
root_hash=b8c0a14d4fa1440e8d624f0fbe1639477d41bcd3cd530317682925dcf09f1835
signature=726ebfe875ca1b54a586ad77a0f28ecadbdc3e3bbff5fb7d8b0dd69aa1a3195a30082e51b1982a70228ac455ef0d5da329bcaacc08a9dcf0dbc765fe0cc18400
cosignature=0d4f46a219ab309cea48cde9712e7d8486fc99802f873175eeab70fb84b4f5a4 1759300864 e1eb12119f68cb07199747398f94fae281529a138ab13e23842ff9c55c722cb1b036f0f378d5f8950f2cdac0ffd262550e57a8fe493dceece72652dce65ba60d
cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1759300864 fc44071f94fe33b4de857f60b4dc1703b59c8623147d68f99b1a4275bbc6897b40c23a3d03d2c20e098ac1016f73258ebcaeeeeef2fa585106be9f49e26ccc0f

leaf_index=8857
node_hash=9736194936496bfbea6e571fad7f34519f32a1132c340cff8ae6c071a4ba7320
node_hash=42fb1dfd5f0610ae4e61f91b644c3794a24d1084331db464096beb7c0c9dc11b
node_hash=1c0df8227e8a3a76ab618d421c89afa3923ea5c74c025eec0c53a1109d4c9d28
node_hash=91bc923fa508d27f12ddeae047e7b51a7bb5cc529b173836d66bdd8728eab5c9
node_hash=ca6768bb0e267f5c339e639f02101c73be12efd5dd0462959677a86e22bbb58d
node_hash=e8bb977d7ae35a4b7e591ded5e3d7fad0afee0b958d6309a52f48fe46c679c36
")?;
assert!(verify(&Hash::new(data), signature, signers, &policy).is_ok());
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

License: MIT
