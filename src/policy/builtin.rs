use super::Policy;

const SIGSUM_TEST1_2025: &str = include_str!("sigsum-test1-2025.builtin-policy");
const SIGSUM_TEST2_2025: &str = include_str!("sigsum-test2-2025.builtin-policy");
const SIGSUM_TEST_2025_3: &str = include_str!("sigsum-test-2025-3.builtin-policy");
const SIGSUM_GENERIC_2025_1: &str = include_str!("sigsum-generic-2025-1.builtin-policy");

impl Policy {
    pub fn builtin(name: &str) -> Option<Self> {
        match name {
            "sigsum-test1-2025" => Some(Policy::parse(SIGSUM_TEST1_2025).unwrap()),
            "sigsum-test2-2025" => Some(Policy::parse(SIGSUM_TEST2_2025).unwrap()),
            "sigsum-test-2025-3" => Some(Policy::parse(SIGSUM_TEST_2025_3).unwrap()),
            "sigsum-generic-2025-1" => Some(Policy::parse(SIGSUM_GENERIC_2025_1).unwrap()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_builtin_policies() {
        assert!(Policy::builtin("sigsum-test1-2025").is_some());
        assert!(Policy::builtin("sigsum-test2-2025").is_some());
        assert!(Policy::builtin("sigsum-test-2025-3").is_some());
        assert!(Policy::builtin("sigsum-generic-2025-1").is_some());
    }
}
