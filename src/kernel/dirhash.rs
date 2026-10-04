//! Go module dirhash verification (golang.org/x/mod/sumdb/dirhash Hash1).
//!
//! go.sum's `h1:` values are NOT hashes of the zip bytes — they hash the
//! module's file *list*: one line per file, `<sha256 hex>  <name>\n`,
//! sorted, then sha256 of the concatenation, base64-encoded. Tog
//! verifies these itself so Go module bytes enter the kernel's front door
//! under tog's own check, not go's.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Hash1 over a module zip: entries are named `<module>@<version>/<path>`
/// and hashed uncompressed. Rejects entries outside the module prefix,
/// backslashes, and newlines (Hash1's own rules).
pub fn hash_zip(zip_path: &Path, module: &str, version: &str) -> io::Result<String> {
    let file = fs::File::open(zip_path)
        .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", zip_path.display())))?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| err(format!("{}: not a zip: {e}", zip_path.display())))?;
    let prefix = format!("{module}@{version}/");
    let mut lines = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| err(format!("{}: zip entry {i}: {e}", zip_path.display())))?;
        let name = entry.name().to_string();
        if name.ends_with('/') {
            continue; // directory entry
        }
        if !name.starts_with(&prefix) || name.contains('\\') || name.contains('\n') {
            return Err(err(format!(
                "{}: zip entry {name:?} escapes module prefix {prefix:?}",
                zip_path.display()
            )));
        }
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        lines.push((name, hex::encode(hasher.finalize())));
    }
    Ok(hash1(lines))
}

/// Hash1 for a `/go.mod` go.sum entry: a single file named exactly "go.mod".
pub fn hash_gomod(file_path: &Path) -> io::Result<String> {
    let content = fs::read(file_path)
        .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", file_path.display())))?;
    Ok(hash1(vec![(
        "go.mod".to_string(),
        hex::encode(Sha256::digest(&content)),
    )]))
}

/// Hash1 sorts by FILE NAME (not by composed line), then hashes
/// `<hex>  <name>\n` lines in that order.
fn hash1(mut files: Vec<(String, String)>) -> String {
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (name, hex) in &files {
        hasher.update(format!("{hex}  {name}\n").as_bytes());
    }
    format!("h1:{}", crate::kernel::base64::encode(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/go-dirhash")
            .join(name)
    }

    #[test]
    fn real_module_zip_reproduces_gosum_h1() {
        // Real rsc.io/quote v1.5.2 zip; expected value is its go.sum line.
        let h = hash_zip(&fixture("quote-v1.5.2.zip"), "rsc.io/quote", "v1.5.2").unwrap();
        assert_eq!(h, "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=");
    }

    #[test]
    fn real_gomod_reproduces_gosum_h1() {
        let h = hash_gomod(&fixture("quote-v1.5.2.mod")).unwrap();
        assert_eq!(h, "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=");
    }

    #[test]
    fn wrong_module_prefix_rejected_and_tamper_changes_hash() {
        let error = hash_zip(&fixture("quote-v1.5.2.zip"), "rsc.io/other", "v1.5.2")
            .expect_err("a zip under another module path was hashed");
        assert!(
            error
                .to_string()
                .contains("escapes module prefix \"rsc.io/other@v1.5.2/\""),
            "{error}"
        );

        let scratch = TempDir::named("dirhash-tamper");
        let tampered = scratch.0.join("go.mod");
        let mut content = fs::read(fixture("quote-v1.5.2.mod")).unwrap();
        content[0] ^= 1;
        fs::write(&tampered, content).unwrap();
        let h = hash_gomod(&tampered).unwrap();
        assert_ne!(h, "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=");
    }
}
