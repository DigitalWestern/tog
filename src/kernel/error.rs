//! Failure classes (kernel layer): what kind of failure an error is, for
//! the failures whose kind decides what a script or a CI job does next
//! (#258).
//!
//! Tog's functions return `io::Result`, and an `io::ErrorKind` cannot say
//! "the policy refused this" apart from "a file is corrupt": both are
//! `InvalidData` or `PermissionDenied` somewhere. So a failure that belongs
//! to one of the classes below carries a [`Classified`] value inside its
//! `io::Error`, the same way a refused store carries
//! `store::format::Refused`. Its `kind()` stays what it always was, so
//! nothing that matches on kinds changes. `main` reads the class with
//! [`class_of`] and exits with the class's own status, so a script can
//! tell a stale lock from a denied exception without parsing the message.
//!
//! An error with no class is an ordinary failure (exit 1). A signal that
//! stopped tog is not a class here: `supervise::stop_signal` already
//! reports it, and `main` exits `128 + signal` for it.
//!
//! A caller that adds words to an error must keep its class: [`context`]
//! does, where `io::Error::new(e.kind(), format!(..))` keeps only the text.

use std::fmt;
use std::io;

/// A failure class whose exit status is its own (see `docs/human/CLI.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Tog will not do this, by rule: a policy denial, a project directory
    /// swapped for a symlink, a store it will not open. Running it again
    /// changes nothing; the policy or the input has to.
    Refused,
    /// A committed file no longer describes what it should (a stale
    /// `tog-toolchain.toml`), or is missing where `--frozen` or a strict
    /// policy never writes one. The fix is to update it and commit it.
    Stale,
    /// Something this tog or this machine does not support.
    Unsupported,
    /// The network failed. Running it again may work.
    Network,
}

impl Class {
    /// The process exit status `main` uses for this class.
    pub fn exit_code(self) -> i32 {
        match self {
            Class::Refused => 3,
            Class::Stale => 4,
            Class::Unsupported => 5,
            Class::Network => 6,
        }
    }

    /// The class's name as `--json` errors spell it.
    pub fn name(self) -> &'static str {
        match self {
            Class::Refused => "refused",
            Class::Stale => "stale",
            Class::Unsupported => "unsupported",
            Class::Network => "network",
        }
    }
}

/// The value a classified `io::Error` carries: the class and the message.
#[derive(Debug)]
pub struct Classified {
    pub class: Class,
    message: String,
}

impl fmt::Display for Classified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Classified {}

/// An `io::Error` of `kind` that says `message` and belongs to `class`.
pub fn new(class: Class, kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
    io::Error::new(
        kind,
        Classified {
            class,
            message: message.into(),
        },
    )
}

/// A refusal by rule (see [`Class::Refused`]).
pub fn refused(kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
    new(Class::Refused, kind, message)
}

/// A stale or missing committed file (see [`Class::Stale`]).
pub fn stale(kind: io::ErrorKind, message: impl Into<String>) -> io::Error {
    new(Class::Stale, kind, message)
}

/// The class of `error`, if it has one. Besides a carried [`Classified`],
/// a refused store is `Refused`, an `Unsupported` kind is `Unsupported`,
/// and a server status a retry can change (`fetch::retry_may_help`) is
/// `Network`: each already says exactly that.
pub fn class_of(error: &io::Error) -> Option<Class> {
    if let Some(classified) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Classified>())
    {
        return Some(classified.class);
    }
    if crate::kernel::store::refusal_fix(error).is_some() {
        return Some(Class::Refused);
    }
    if crate::kernel::fetch::retry_may_help(error) {
        return Some(Class::Network);
    }
    (error.kind() == io::ErrorKind::Unsupported).then_some(Class::Unsupported)
}

/// `error` with `what` in front of its message (`what: message`), keeping
/// its kind and its class.
pub fn context(error: io::Error, what: impl fmt::Display) -> io::Error {
    let message = format!("{what}: {error}");
    match class_of(&error) {
        Some(class) => new(class, error.kind(), message),
        None => io::Error::new(error.kind(), message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_class_rides_inside_the_error_and_keeps_its_kind() {
        let error = refused(io::ErrorKind::InvalidData, "swapped");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "swapped");
        assert_eq!(class_of(&error), Some(Class::Refused));
        let plain = io::Error::new(io::ErrorKind::InvalidData, "corrupt");
        assert_eq!(class_of(&plain), None);
    }

    #[test]
    fn context_keeps_the_class_and_the_kind() {
        let wrapped = context(stale(io::ErrorKind::NotFound, "lock missing"), "sync");
        assert_eq!(wrapped.to_string(), "sync: lock missing");
        assert_eq!(wrapped.kind(), io::ErrorKind::NotFound);
        assert_eq!(class_of(&wrapped), Some(Class::Stale));
        let plain = context(io::Error::other("boom"), "sync");
        assert_eq!(class_of(&plain), None);
    }

    #[test]
    fn an_unsupported_kind_is_the_unsupported_class() {
        let error = io::Error::new(io::ErrorKind::Unsupported, "no such platform");
        assert_eq!(class_of(&error), Some(Class::Unsupported));
    }

    #[test]
    fn every_class_has_its_own_exit_status() {
        let classes = [
            Class::Refused,
            Class::Stale,
            Class::Unsupported,
            Class::Network,
        ];
        let codes: std::collections::BTreeSet<i32> =
            classes.iter().map(|class| class.exit_code()).collect();
        assert_eq!(codes.len(), classes.len());
        // Not the general failure (1), usage (2), or a signal (128 + n).
        assert!(codes.iter().all(|code| (3..128).contains(code)));
    }
}
