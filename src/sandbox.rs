//! Hermetic build sandbox for macOS via sandbox-exec (Seatbelt).
//!
//! Deny-by-default profile: no network, reads limited to declared inputs
//! (store + system runtime), writes limited to the build's private
//! directories. This is a hermeticity mechanism, not containment for
//! hostile code (Sol's framing) — it makes "undeclared network access
//! fails" true, which is what the kernel needs.

use std::io;
use std::path::Path;
use std::process::Command;

pub struct Sandbox<'a> {
    /// Directories the build may read (store objects, staged sources).
    pub read: Vec<&'a Path>,
    /// Directories the build may read AND write (build tmp, output).
    pub write: Vec<&'a Path>,
}

impl Sandbox<'_> {
    fn profile(&self) -> String {
        let mut p = String::from(
            "(version 1)\n\
             (deny default)\n\
             (deny network*)\n\
             ; process basics\n\
             (allow process-exec*)\n\
             (allow process-fork)\n\
             (allow process-info*)\n\
             (allow signal (target same-sandbox))\n\
             (allow sysctl-read)\n\
             (allow mach-lookup)\n\
             ; dyld must map dylibs; without this every exec SIGABRTs\n\
             (allow file-map-executable)\n\
             (allow file-read* (literal \"/\"))\n\
             ; system runtime, read-only\n\
             (allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\")\n\
                (subpath \"/System\") (subpath \"/Library\") (subpath \"/private/etc\")\n\
                (subpath \"/opt\") (subpath \"/var/db/timezone\") (subpath \"/dev\"))\n\
             (allow file-read-metadata)\n\
             (allow file-write-data (literal \"/dev/null\") (literal \"/dev/dtracehelper\"))\n\
             (allow file-write* (subpath \"/private/var/folders\") (subpath \"/private/tmp\"))\n",
        );
        for r in &self.read {
            p.push_str(&format!("(allow file-read* (subpath {:?}))\n", r.display().to_string()));
        }
        for w in &self.write {
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath {:?}))\n",
                w.display().to_string()
            ));
        }
        p
    }

    /// Run `cmd` inside the sandbox with a scrubbed environment.
    /// `env_path` becomes PATH; HOME/TMPDIR point into the writable tmp.
    pub fn run(&self, cmd: &[&str], env_path: &str, tmp: &Path) -> io::Result<()> {
        let profile = self.profile();
        let status = Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(&profile)
            .args(cmd)
            .current_dir(tmp) // cwd must be readable in-sandbox (getcwd)
            .env_clear()
            .env("PATH", env_path)
            .env("HOME", tmp)
            .env("TMPDIR", tmp)
            .env("LANG", "en_US.UTF-8")
            .env("SOURCE_DATE_EPOCH", "315532800") // reproducibility nudge
            .status()?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sandboxed command failed ({status}): {cmd:?}"),
            ));
        }
        Ok(())
    }
}
