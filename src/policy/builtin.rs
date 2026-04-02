//! Built-in policies for Sigsum.
//!
//! This module contains all the included built-in policies. These can be accessed
//! and used directly as public statics, or looked up at runtime by name via
//! [`Policy::builtin`].

#[cfg(feature = "std")]
use core::ops::Deref;
#[cfg(feature = "std")]
use std::sync::LazyLock;

use super::Policy;

/// A built-in policy with a given name.
///
/// The user facing name of this policy can be accessed via the public `name` field.
/// This struct implements `Deref<Target=Policy>`, so using it as a [`Policy`] becomes
/// transparent.
///
/// This policy is parsed and lazily initialized on first use.
#[cfg(feature = "std")]
pub struct BuiltInPolicy {
    /// The user-friendly name of the built-in policy.
    pub name: &'static str,

    policy: LazyLock<Policy>,
}

#[cfg(feature = "std")]
impl BuiltInPolicy {
    /// Returns the policy for this built-in policy. Can also be accessed
    /// via the `Deref` implementation.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

#[cfg(feature = "std")]
impl Deref for BuiltInPolicy {
    type Target = Policy;

    fn deref(&self) -> &Self::Target {
        self.policy()
    }
}

macro_rules! define_builtin_policies {
    ($(
        $(#[$attr:meta])*
        $const_name:ident = $policy_name:literal
    ),* $(,)?) => {
        // Define the static constants
        $(
            #[doc = concat!("`", $policy_name, "`: ")]
            $(#[$attr])*
            #[doc = ""]
            #[doc = "Policy content:"]
            // We include the policy source in the documentation: it's an easy way to provide the
            // user with full information about the policy and it's hard to document a policy
            // without just paraphrasing its content anyway.
            #[doc = "```text"]
            #[doc = include_str!(concat!(
                        "../../builtin-policies/",
                        $policy_name,
                        ".builtin-policy"
                    ))]
            #[doc = "```"]
            #[cfg(feature = "std")]
            pub static $const_name: BuiltInPolicy = BuiltInPolicy {
                name: $policy_name,
                policy: LazyLock::new(|| builtin($policy_name).expect(concat!("Failed to find built-in policy: ", $policy_name))),
            };
        )*

        /// Returns a built-in policy by name, if one exists.
        pub(crate) fn builtin(name: &str) -> Option<Policy> {
            match name {
                $(
                    $policy_name => Some(
                        Policy::parse(include_str!(concat!(
                            "../../builtin-policies/",
                            $policy_name,
                            ".builtin-policy"
                        )))
                        .expect(concat!("Failed to parse built-in policy: ", $policy_name))
                    ),
                )*
                _ => None,
            }
        }

        // Auto-generate tests. Asserts that all policies parse without panicking
        #[cfg(all(test, feature = "std"))]
        mod tests {
            use super::*;

            #[test]
            fn parse_builtin_policies() {
                $(
                    let _policy = $const_name.policy();
                )*
            }
        }
    };
}

// All built-in policies defined here in one single place.
// Multiple invocations not possible since this invocation emits the `builtin` lookup function.
//
// The syntax is
//      /// <doc comment>
//      <static name> = "<policy name>"
//  Where
//      <policy name> is the policy name defined by the Sigsum project
//      <static name> is <policy name> converted to uppercase and with '-' replaced by '_'
define_builtin_policies! {
    /// Policy using the sigsum test log at test.sigsum.org/barreleye
    SIGSUM_TEST1_2025 = "sigsum-test1-2025",
    /// Policy using the sigsum test log at test.sigsum.org/barreleye
    SIGSUM_TEST2_2025 = "sigsum-test2-2025",
    /// Policy using two sigsum test logs at test.sigsum.org/barreleye and serviceberry.tlog.stagemole.eu
    SIGSUM_TEST_2025_3 = "sigsum-test-2025-3",
    /// This is a Sigsum trust policy that has been vetted by the Sigsum project
    SIGSUM_GENERIC_2025_1 = "sigsum-generic-2025-1",
}
