//! The validating resolver: every upstream connection the proxy opens is to
//! an address it looked up once and checked against the IANA
//! special-purpose table ([`super::iana`]).
//!
//! Sandboxed code chooses the paths the proxy fetches, so without this the
//! proxy is a pivot to whatever the host can reach: cloud metadata at
//! `169.254.169.254`, a database on `10.x`, a service on loopback. The
//! lookup happens here, once per connection; every returned address must be
//! globally routable or the whole connection is refused (one private answer
//! among public ones is how a rebinding attack starts); and the HTTP client
//! connects only to the list returned here, never looking the name up
//! again.

use super::iana;
use crate::kernel::fetch::pinned::{PinnedResolve, ResolveRefusal};
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

/// A name lookup. Production asks the system resolver; tests answer from a
/// table (and count the calls).
pub trait Lookup: Send + Sync {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// The system resolver (`getaddrinfo`).
pub struct SystemLookup;

impl Lookup for SystemLookup {
    fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
        Ok((host, port)
            .to_socket_addrs()?
            .map(|address| address.ip())
            .collect())
    }
}

/// Looks up once, validates every address, returns exactly that list.
pub struct ValidatingResolver {
    lookup: Arc<dyn Lookup>,
    /// Tests only: accept loopback answers, so the fixture upstream on
    /// `127.0.0.1` is reachable. Every other refused range stays refused,
    /// and the SSRF tests build their resolver with this off.
    #[cfg(test)]
    pub(crate) allow_loopback: bool,
    /// Tests only: where a validated address actually connects. The rebinding
    /// test validates a public answer and lands it on a local listener.
    #[cfg(test)]
    pub(crate) connect_to: Option<Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>>,
}

impl ValidatingResolver {
    pub fn new(lookup: Arc<dyn Lookup>) -> Self {
        Self {
            lookup,
            #[cfg(test)]
            allow_loopback: false,
            #[cfg(test)]
            connect_to: None,
        }
    }

    /// Why `address` may not be connected to, if it may not.
    fn refusal(&self, address: IpAddr) -> Option<String> {
        #[cfg(test)]
        // `is_loopback` is `127.0.0.0/8` and `::1` only: an IPv4-mapped
        // `::ffff:127.0.0.1` is not loopback here and stays refused.
        if self.allow_loopback && address.is_loopback() {
            return None;
        }
        iana::refusal(address)
    }
}

impl PinnedResolve for ValidatingResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let addresses = self.lookup.lookup(host, port)?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{host} resolved to no address"),
            ));
        }
        for address in &addresses {
            if let Some(reason) = self.refusal(*address) {
                return Err(ResolveRefusal(format!(
                    "{host} resolves to {reason}; the proxy connects only to globally routable \
                     addresses"
                ))
                .into_io());
            }
        }
        let validated: Vec<SocketAddr> = addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect();
        #[cfg(test)]
        if let Some(connect_to) = &self.connect_to {
            return Ok(validated.into_iter().map(|a| connect_to(a)).collect());
        }
        Ok(validated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Answers from a fixed table.
    struct Table(Vec<IpAddr>, Mutex<usize>);

    impl Lookup for Table {
        fn lookup(&self, _host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
            *self.1.lock().unwrap() += 1;
            Ok(self.0.clone())
        }
    }

    fn resolver(answers: &[&str]) -> ValidatingResolver {
        ValidatingResolver::new(Arc::new(Table(
            answers.iter().map(|a| a.parse().unwrap()).collect(),
            Mutex::new(0),
        )))
    }

    fn refused(error: io::Error) -> String {
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ResolveRefusal>())
            .map(|refusal| refusal.0.clone())
            .unwrap_or_else(|| panic!("not a refusal: {error}"))
    }

    #[test]
    fn every_answer_must_be_global() {
        let ok = resolver(&["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]);
        assert_eq!(ok.resolve("registry.test", 443).unwrap().len(), 2);
        for private in ["10.0.0.1", "169.254.169.254", "::ffff:10.0.0.1", "fd00::1"] {
            let mixed = resolver(&["93.184.216.34", private]);
            let why = refused(mixed.resolve("registry.test", 443).unwrap_err());
            assert!(why.contains("registry.test"), "{why}");
        }
    }

    #[test]
    fn the_loopback_exception_is_loopback_only() {
        let mut local = resolver(&["127.0.0.1"]);
        refused(local.resolve("fixture.test", 443).unwrap_err());
        local.allow_loopback = true;
        assert!(local.resolve("fixture.test", 443).is_ok());
        let mut mapped = resolver(&["::ffff:127.0.0.1"]);
        mapped.allow_loopback = true;
        refused(mapped.resolve("fixture.test", 443).unwrap_err());
        let mut private = resolver(&["10.0.0.1"]);
        private.allow_loopback = true;
        refused(private.resolve("fixture.test", 443).unwrap_err());
    }
}
