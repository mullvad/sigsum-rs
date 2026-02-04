//! sigsum-rs is a Rust implementation of the Sigsum library. It currently only
//! supports offline verification of sigsum signatures but aims to eventually
//! include submitting and monitoring.
//!
//! # Installation
//!
//! Add sigsum to your Rust project with [cargo](https://doc.rust-lang.org/cargo/).
//!
//! ```bash
//! cargo add sigsum
//! ```
//!
//! # Usage
//!
//! ```rust
//! # use std::error::Error;
//! use sigsum::{verify, Hash, PublicKey, SigsumSignature};
//! use hex_literal::hex;
//!
//! let data = b"Hello, Sigsum!\n";
//! let signers: Vec<PublicKey> =
//!     vec![hex!("99ed58583e8750b20548e69df4a4e1a592379a9a66c51cd32e42fbe4e1bde78a").into()];
//! let signature = SigsumSignature::from_ascii("version=2
//! log=1643169b32bef33a3f54f8a353b87c475d19b6223cbb106390d10a29978e1cba
//! leaf=2c8d843ed6237e9ea033207113329fdd1428c75f8fd3c6782ae46c92c7a00c40 38dd0b42cab5166611a4f8346db1c6ffe81ee2345f3ffe36a466eb8fce1d4b2879fbb5f26291d25e610b2dc7f30eaa603efd97739ae585657d0f7181726eec00
//!
//! size=381382
//! root_hash=901fefc6f1d978d2c2bedb82d448755bcdc7e8626e67ac7ee80873771be9b667
//! signature=8a8bf1fca60d1344fb6e2106e8f8906af833d3d75a21fe8d3af72be459f7a11f2ae6606ec6344a13b851cd454b3d281a2b1ae47732f7a8d6afbcc0134d1a2d00
//! cosignature=1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c 1770193051 a1ee1182b265204499cbef3ae59f3ea228b928b3cbda8817a4ed5a12776823e9ad8ef1ce986b9b98d9954f1798ec4315c1820704600a231c69038ccc9726d202
//! cosignature=49c4cd6124b7c572f3354d854d50b2a4b057a750f786cf03103c09de339c4ea3 1770193051 aaf642e81a54399777180f238573d74878b68c7b645d8011583621405bb450b4e7887fc76502a8142c493d64e3ed3e556d82dad1706411082e58805f64fa9d02
//! cosignature=70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc 1770193051 f5953f406f5fd97d9c9d1328b00b07bf434a5eb76d8da359aeda98c414de29ca1ced1872971ea0f137508a7bb05c7d322548409425677af96433706319bc0801
//! cosignature=86b5414ae57f45c2953a074640bb5bedebad023925d4dc91a31de1350b710089 1770193051 3434b4646904714f4983c8e7e976a45332711f10012b19fbeb5549b6c0c04fb4ed52feed2da829354623c52b22b90093776034a8d57d660f9ff27a118f5bf801
//! cosignature=c1d2d6935c2fb43bef395792b1f3c1dfe4072d4c6cadd05e0cc90b28d7141ed3 1770193051 f0dce1bcdda3a2826479d62e6afedbe9ec06e8f990ae59d8cefa84d9a6ee68c12c2820fb00e1dbdc30044b16c7695a9d1047cec4788dc757f698d34ebaec4305
//! cosignature=d960fcff859a34d677343e4789c6843e897c9ff195ea7140a6ef382566df3b65 1770193051 b44c41f75566850003f7f655a6dc7bb38bb980e8e2c383871e29883805d3adec7782a08388b9386d9718380a4bb6900043e2b46080cff0fa75a500c36ef9df0a
//! cosignature=e4a6a1e4657d8d7a187cc0c20ed51055d88c72f340d29534939aee32d86b4021 1770193051 70697b4a6b07e79e49d0a8e41fd7450a593ee9df11da6244cebe4b0c15c8e52f28ad3931b95a806fc7f16b4ad90197971ddc087434c7985b8b3a0223c9fa3603
//! cosignature=42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8 1770193051 6610e5cf4ead2062d9783fbc19d2bae65eded35335495ad0cf0386277ed2d51854ced64efa21a6db0a398fdfb6761aa7d5659e54950a060d167fbdcb7b5ece05
//!
//! leaf_index=381381
//! node_hash=d009c5dbeaaa5be1788ea9533f6f398747755a8245012165ac73f753b7917672
//! node_hash=fb515551fe18f6e53d7d7f49b80abbb5c702b9662ee74fc7730e4a7685000aa4
//! node_hash=e21e73ee8caf0d49cdcd2f334b3f64e85e4a151daf8d09b6034306bb21b88480
//! node_hash=f77bc4db00e509149b6e2fc0028d7107dd415929dc9972f32fe758ce39bcc9a0
//! node_hash=3acb38f01c633d917b899ed4e522a49a02bf20d358f98ca530e3a3065591e7f2
//! node_hash=889de80c543a5ae8e35430988dc120ac7edde74b776f9082f814ea88190a601f
//! node_hash=199f812b9f3667dec31f964098e32652477a2f3d458019b6f8f4acc645cf0131
//! node_hash=084580f8f6324d4ae42dbcb779502ab9fab77e0c2b92519fe089be72e38d60ed
//! node_hash=9ddbece4939d621df53f31e2729d5fa7802fd82f3edfb784483d8b7fa9cf41e2
//! node_hash=e1c7a90c09949c263807e5970aef47f9a06164b759995ab814aff94aff9dcd00
//! ")?;
//!
//! verify(&Hash::new(data), signature, signers, &sigsum::policy::SIGSUM_TEST_2025_3)?;
//! # Ok::<(), Box<dyn Error>>(())
//! ```
//!
//! # Contributing
//!
//! Pull requests are welcome. For major changes, please open an issue first
//! to discuss what you would like to change.
//!
//! Please make sure to update tests as appropriate.

mod io {
    pub(crate) mod ascii;
}
mod crypto;
mod log;
mod merkle;
pub mod policy;
mod sigsumsig;
mod verify;

pub use crypto::{Hash, PublicKey, Signature};
pub use io::ascii::ParseAsciiError;
pub use log::{InclusionProof, Leaf, Protoleaf, SignedTreeHead, WitnessCosignature};
pub use policy::{Policy, PolicyBuilder};
pub use sigsumsig::SigsumSignature;
pub use verify::{verify, VerifyError};
