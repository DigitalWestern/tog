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
    let public = signing::generate(path)?;
    ui::note(&format!(
        "keygen: wrote {} (mode 0600). Keep it outside the checkout, the store, and any sandbox read root; set TOG_SIGNING_KEY={} where 'tog sync' runs",
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

    #[test]
    fn the_printed_snippet_is_a_policy_that_trusts_the_key() {
        let temp = std::env::temp_dir().join(format!(
            "tog-keygen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let path = temp.join("key");
        let public = signing::generate(&path).unwrap();
        let snippet = policy_snippet(&public);
        let parsed = policy::parse_file(Path::new("policy.toml"), &snippet).unwrap();
        assert_eq!(
            parsed.signing.unwrap().trusted,
            [public].into_iter().collect()
        );
        assert!(!snippet.contains(&std::fs::read_to_string(&path).unwrap().trim()[8..]));
        let _ = std::fs::remove_dir_all(temp);
    }
}
