//! `tog keygen <path>`: create a closure-signing key and print the
//! `[signing]` policy table that trusts it.
//!
//! The key file is created exclusively with mode 0600 and never overwrites
//! anything; the seed is never printed. Only the public key goes to stdout,
//! as the exact lines to paste into the machine policy.

use crate::kernel::signing;
use crate::kernel::ui;
use std::io;
use std::path::Path;

pub fn run(path: &Path) -> io::Result<i32> {
    // Every sandbox, resolution doors included, can read the system
    // directories; a key there is readable by the code tog runs.
    crate::kernel::resolve::confine::refuse_key_under_system_root(path)?;
    let public = signing::generate(path)?;
    ui::note(&format!(
        "keygen: wrote {} (mode 0600). Keep it outside the checkout, the store, and any sandbox read root; set TOG_SIGNING_KEY={} where 'tog' runs",
        path.display(),
        path.display()
    ));
    print!("{}", policy_snippet(&public));
    Ok(0)
}

/// The `[signing]` table that trusts exactly `public`.
pub fn policy_snippet(public: &signing::PublicKey) -> String {
    format!("[signing]\ntrusted = [\"{public}\"]\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn keygen_refuses_a_path_under_a_system_read_root() {
        let error = run(Path::new("/etc/tog/signing.key")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!Path::new("/etc/tog/signing.key").exists());
    }

    #[test]
    fn the_printed_snippet_is_a_policy_that_trusts_the_key() {
        let temp = TempDir::named("keygen");
        let path = temp.0.join("key");
        let public = signing::generate(&path).unwrap();
        let snippet = policy_snippet(&public);
        let parsed = policy::parse_file(Path::new("policy.toml"), &snippet).unwrap();
        assert_eq!(
            parsed.signing.unwrap().trusted,
            [public].into_iter().collect()
        );
        assert!(!snippet.contains(&std::fs::read_to_string(&path).unwrap().trim()[8..]));
    }
}
