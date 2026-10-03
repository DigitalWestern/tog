//! The resolution proxy's certificate authority: what lets it read the
//! requests of a tool that speaks https (cargo, git, and later npm and uv).
//!
//! One authority per tog process, made when the proxy starts: an ECDSA
//! P-256 key generated through `ring` that never leaves memory, and a
//! self-signed certificate that may sign only server leaves (path length
//! 0). A door that intercepts writes the certificate (never the key) into
//! its session directory and binds it read-only into the sandbox, where the
//! tool is told to trust it (`http.cainfo`, `http.sslCAInfo`). The system
//! and user trust stores are never touched.
//!
//! A leaf is minted per intercepted host on first use and kept for the
//! process, with the TLS server configuration that serves it: the `ring`
//! provider named explicitly, only `http/1.1` offered by ALPN, and a
//! certificate resolver that refuses a handshake whose server name is not
//! the host the tunnel was opened for.

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// How long the authority and its leaves are valid, in days either side of
/// today. A tog process lives minutes; the margin absorbs clock skew
/// between the host and nothing else (the sandbox shares its clock).
const VALID_BEFORE_DAYS: i64 = 1;
const VALID_AFTER_DAYS: i64 = 30;

/// The longest host name a leaf is minted for (DNS's own limit).
const MAX_HOST: usize = 253;

/// The process's certificate authority and the leaves it has minted.
pub struct Authority {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
    /// One key for every leaf: minting is a signature, not a key
    /// generation, and the leaf key is as private as the CA's.
    leaf_key: rcgen::KeyPair,
    leaf_signer: Arc<dyn rustls::sign::SigningKey>,
    pem: String,
    provider: Arc<CryptoProvider>,
    configs: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl Authority {
    /// A fresh authority: new keys, a new self-signed certificate.
    pub fn new() -> io::Result<Authority> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = generate_key()?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(tls_error)?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "tog resolution proxy (this tog process only)",
        );
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        validity(&mut params);
        params.serial_number = Some(serial()?);
        let cert = params.self_signed(&key).map_err(tls_error)?;
        let pem = cert.pem();
        let leaf_key = generate_key()?;
        let leaf_signer = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            )))
            .map_err(tls_error)?;
        Ok(Authority {
            cert,
            key,
            leaf_key,
            leaf_signer,
            pem,
            provider,
            configs: Mutex::new(HashMap::new()),
        })
    }

    /// The certificate in PEM, the file a tool is told to trust.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// The certificate itself.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        self.cert.der()
    }

    /// A root set holding only this authority, for a client in tog's own
    /// tests that plays the tool.
    pub fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.cert.der().clone())
            .expect("the authority's own certificate parses");
        roots
    }

    /// The TLS server configuration for a tunnel to `host`, minted on first
    /// use and kept for the process. `host` is a lowercase DNS name or an IP
    /// literal (without brackets).
    pub(crate) fn server_config(&self, host: &str) -> io::Result<Arc<rustls::ServerConfig>> {
        check_host(host)?;
        let mut configs = self
            .configs
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(config) = configs.get(host) {
            return Ok(config.clone());
        }
        let leaf = self.mint(host)?;
        let mut config = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(tls_error)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(ForHost {
                host: host.to_string(),
                key: Arc::new(leaf),
            }));
        // HTTP/2 is never offered: the proxy speaks the HTTP/1.1 subset
        // only. Tools that prefer h2 fall back to parallel connections.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        configs.insert(host.to_string(), config.clone());
        Ok(config)
    }

    /// A leaf for `host`, signed by this authority.
    fn mint(&self, host: &str) -> io::Result<CertifiedKey> {
        let mut params =
            rcgen::CertificateParams::new(vec![host.to_string()]).map_err(tls_error)?;
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        validity(&mut params);
        params.serial_number = Some(serial()?);
        let leaf = params
            .signed_by(&self.leaf_key, &self.cert, &self.key)
            .map_err(tls_error)?;
        Ok(CertifiedKey::new(
            vec![leaf.der().clone()],
            self.leaf_signer.clone(),
        ))
    }
}

/// Serves one host's leaf, and nothing to a client that names another
/// server: a tunnel opened for one host cannot be used to speak to another.
#[derive(Debug)]
struct ForHost {
    host: String,
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for ForHost {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match hello.server_name() {
            Some(name) if !name.eq_ignore_ascii_case(&self.host) => None,
            _ => Some(self.key.clone()),
        }
    }
}

/// Whether `host` is something a leaf may name: an IP literal, or a DNS
/// name of lowercase letters, digits, `-` and `.` with no empty label.
pub(crate) fn check_host(host: &str) -> io::Result<()> {
    let refuse = |why: &str| {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{host:?} is not a host the proxy intercepts: {why}"),
        ))
    };
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if host.is_empty() || host.len() > MAX_HOST {
        return refuse("empty or too long");
    }
    let plain = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !host.split('.').all(plain) {
        return refuse("not a lowercase DNS name");
    }
    Ok(())
}

fn generate_key() -> io::Result<rcgen::KeyPair> {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(tls_error)
}

/// 16 random bytes with the top bit clear, so the DER integer is positive.
fn serial() -> io::Result<rcgen::SerialNumber> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("the system random source failed"))?;
    bytes[0] &= 0x7f;
    Ok(rcgen::SerialNumber::from_slice(&bytes))
}

/// Valid from yesterday to a month from now.
fn validity(params: &mut rcgen::CertificateParams) {
    let today = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| (since.as_secs() / 86_400) as i64);
    let date = |days: i64| {
        let (year, month, day) = civil_from_days(days);
        rcgen::date_time_ymd(year, month, day)
    };
    params.not_before = date(today - VALID_BEFORE_DAYS);
    params.not_after = date(today + VALID_AFTER_DAYS);
}

/// The proleptic Gregorian (year, month, day) of a day count since
/// 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}

fn tls_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("the proxy's certificate authority: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_match_known_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_729), (2026, 10, 3));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn leaves_are_minted_only_for_plain_hosts() {
        for host in ["index.crates.io", "github.com", "127.0.0.1", "::1", "a-b.c"] {
            check_host(host).unwrap();
        }
        for host in [
            "",
            "Index.crates.io",
            "a..b",
            "-a.b",
            "a b",
            "a_b.c",
            "evil.com\0x",
            "*.crates.io",
        ] {
            assert!(check_host(host).is_err(), "{host:?}");
        }
    }

    /// One configuration per host, kept for the process; a leaf names its
    /// host, is not a CA, and chains to the authority.
    #[test]
    fn interception_mints_leaf_for_sni_host_signed_by_session_ca() {
        let authority = Authority::new().unwrap();
        let first = authority.server_config("index.crates.io").unwrap();
        let again = authority.server_config("index.crates.io").unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(first.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let leaf = authority.mint("index.crates.io").unwrap();
        let der = leaf.cert[0].clone();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(authority.roots()),
            authority.provider.clone(),
        )
        .build()
        .unwrap();
        use rustls::client::danger::ServerCertVerifier;
        let name = rustls::pki_types::ServerName::try_from("index.crates.io").unwrap();
        verifier
            .verify_server_cert(&der, &[], &name, &[], rustls::pki_types::UnixTime::now())
            .unwrap();
        let other = rustls::pki_types::ServerName::try_from("static.crates.io").unwrap();
        assert!(verifier
            .verify_server_cert(&der, &[], &other, &[], rustls::pki_types::UnixTime::now())
            .is_err());
        assert!(authority.pem().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!authority.pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn every_process_authority_is_new() {
        let (a, b) = (Authority::new().unwrap(), Authority::new().unwrap());
        assert_ne!(a.certificate(), b.certificate());
    }
}
