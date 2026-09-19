//! Host platform detection (kernel layer): the only place that knows what
//! machine tog is running on. Everything else takes an explicit `Platform`.

use std::env::consts::{ARCH, OS};
use std::io;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Platform {
    Aarch64AppleDarwin,
    X86_64UnknownLinuxGnu,
}

impl Platform {
    /// Host platform from std::env::consts::{OS, ARCH}. Cached (OnceLock).
    pub fn host() -> io::Result<Platform> {
        static HOST: OnceLock<Result<Platform, String>> = OnceLock::new();
        match HOST.get_or_init(|| match (OS, ARCH) {
            ("macos", "aarch64") => Ok(Platform::Aarch64AppleDarwin),
            ("linux", "x86_64") => {
                if Path::new("/lib64/ld-linux-x86-64.so.2").exists() {
                    Ok(Platform::X86_64UnknownLinuxGnu)
                } else {
                    Err("unsupported host: Linux x86_64 without glibc (musl?) — tog pins glibc toolchains (unsupported platform)".to_string())
                }
            }
            _ => Err(format!(
                "unsupported host platform {OS}/{ARCH}: tog is pinned for aarch64-apple-darwin and x86_64-unknown-linux-gnu (unsupported platform)"
            )),
        }) {
            Ok(platform) => Ok(*platform),
            Err(message) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                message.clone(),
            )),
        }
    }

    pub fn triple(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "aarch64-apple-darwin",
            Platform::X86_64UnknownLinuxGnu => "x86_64-unknown-linux-gnu",
        }
    }

    /// The platform a recorded triple names, if tog supports it.
    pub fn from_triple(triple: &str) -> Option<Platform> {
        Platform::ALL.iter().copied().find(|p| p.triple() == triple)
    }

    pub fn node_slug(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "darwin-arm64",
            Platform::X86_64UnknownLinuxGnu => "linux-x64",
        }
    }

    pub fn go_slug(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "darwin-arm64",
            Platform::X86_64UnknownLinuxGnu => "linux-amd64",
        }
    }

    pub fn dotnet_rid(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "osx-arm64",
            Platform::X86_64UnknownLinuxGnu => "linux-x64",
        }
    }

    pub fn npm_os(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "darwin",
            Platform::X86_64UnknownLinuxGnu => "linux",
        }
    }

    pub fn npm_cpu(self) -> &'static str {
        match self {
            Platform::Aarch64AppleDarwin => "arm64",
            Platform::X86_64UnknownLinuxGnu => "x64",
        }
    }

    pub fn is_macos(self) -> bool {
        matches!(self, Platform::Aarch64AppleDarwin)
    }

    pub const ALL: &'static [Platform] = &[
        Platform::Aarch64AppleDarwin,
        Platform::X86_64UnknownLinuxGnu,
    ];
}

/// Uniform "no pin" error used by every tailor.
pub fn no_pin(what: &str, platform: Platform) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "no {what} pinned for {} (unsupported platform)",
            platform.triple()
        ),
    )
}

pub fn require_host(platform: Platform, what: &str) -> io::Result<()> {
    let host = Platform::host()?;
    if platform == host {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "cannot realize {what} for {} on host {} (unsupported platform)",
            platform.triple(),
            host.triple()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matches_test_machine() {
        let expected = match (OS, ARCH) {
            ("macos", "aarch64") => Platform::Aarch64AppleDarwin,
            ("linux", "x86_64") => Platform::X86_64UnknownLinuxGnu,
            _ => panic!("unsupported test machine {OS}/{ARCH}"),
        };
        assert_eq!(Platform::host().unwrap(), expected);
    }

    #[test]
    fn triples_are_unique_and_darwin_is_stable() {
        assert_eq!(
            Platform::Aarch64AppleDarwin.triple(),
            "aarch64-apple-darwin"
        );
        assert_ne!(
            Platform::Aarch64AppleDarwin.triple(),
            Platform::X86_64UnknownLinuxGnu.triple()
        );
    }

    #[test]
    fn from_triple_round_trips_and_refuses_strangers() {
        for platform in Platform::ALL {
            assert_eq!(Platform::from_triple(platform.triple()), Some(*platform));
        }
        assert_eq!(Platform::from_triple("x86_64-apple-darwin"), None);
        assert_eq!(Platform::from_triple(""), None);
    }

    #[test]
    fn no_pin_names_platform() {
        let error = no_pin("nodejs", Platform::X86_64UnknownLinuxGnu);
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let text = error.to_string();
        assert!(text.contains("x86_64-unknown-linux-gnu"));
        assert!(text.contains("unsupported platform"));
    }
}
