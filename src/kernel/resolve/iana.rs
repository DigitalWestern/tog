//! The address ranges the resolution proxy never connects to, compiled from
//! the IANA IPv4 and IPv6 Special-Purpose Address Registries.
//!
//! Pinned to the registries as updated on [`REGISTRY_DATE`]. The checked-in
//! copies under `tests/fixtures/proxy/iana/` are what the table is tested
//! against: every row whose "Globally Reachable" column is not `True` must
//! be covered here. The table refuses more than that, deliberately, in the
//! fail-closed direction:
//!
//! - three IPv4 blocks the registry marks globally reachable are refused
//!   anyway: AS112 (`192.31.196.0/24`, `192.175.48.0/24`) and AMT
//!   (`192.52.193.0/24`). They hold DNS sinks and relay anycast, never a
//!   package registry;
//! - multicast (`224.0.0.0/4`, `ff00::/8`) is not a special-purpose row at
//!   all but is never a unicast upstream;
//! - every IPv6 form that embeds an IPv4 address is refused outright
//!   instead of being unpacked and judged by its IPv4 half: IPv4-mapped,
//!   IPv4-compatible (`::/96`, deprecated and not a registry row), both
//!   NAT64 prefixes (`64:ff9b::/96` is marked globally reachable), 6to4, and
//!   Teredo;
//! - outside the table, only IPv6 global unicast (`2000::/3`) is eligible.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

/// The `<updated>` date of both registries the table was compiled from.
pub const REGISTRY_DATE: &str = "2025-10-09";

/// One refused block: `(prefix, name)`. Order is only for reading.
const V4: &[(&str, &str)] = &[
    ("0.0.0.0/8", "\"this network\""),
    ("10.0.0.0/8", "private use"),
    ("100.64.0.0/10", "shared address space (CGNAT)"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link local"),
    ("172.16.0.0/12", "private use"),
    ("192.0.0.0/24", "IETF protocol assignments"),
    ("192.0.2.0/24", "documentation (TEST-NET-1)"),
    ("192.31.196.0/24", "AS112-v4"),
    ("192.52.193.0/24", "AMT"),
    ("192.88.99.0/24", "deprecated 6to4 relay anycast"),
    ("192.168.0.0/16", "private use"),
    ("192.175.48.0/24", "direct delegation AS112 service"),
    ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "documentation (TEST-NET-2)"),
    ("203.0.113.0/24", "documentation (TEST-NET-3)"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("255.255.255.255/32", "limited broadcast"),
];

const V6: &[(&str, &str)] = &[
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("::ffff:0:0/96", "IPv4-mapped (embeds an IPv4 address)"),
    ("::/96", "IPv4-compatible (embeds an IPv4 address)"),
    ("64:ff9b::/96", "NAT64 (embeds an IPv4 address)"),
    ("64:ff9b:1::/48", "local-use NAT64 (embeds an IPv4 address)"),
    ("100::/64", "discard-only"),
    ("100:0:0:1::/64", "dummy IPv6 prefix"),
    ("2001::/23", "IETF protocol assignments"),
    ("2001::/32", "Teredo (embeds an IPv4 address)"),
    ("2001:db8::/32", "documentation"),
    ("2002::/16", "6to4 (embeds an IPv4 address)"),
    ("3fff::/20", "documentation"),
    ("5f00::/16", "segment routing (SRv6) SIDs"),
    ("fc00::/7", "unique local"),
    ("fe80::/10", "link-local unicast"),
    ("ff00::/8", "multicast"),
];

/// A parsed block of either family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    V4 { network: u32, len: u8 },
    V6 { network: u128, len: u8 },
}

impl Block {
    /// Parse `a.b.c.d/n` or `x::y/n`. The network must have no host bits.
    pub fn parse(text: &str) -> Option<Block> {
        let (address, len) = text.split_once('/')?;
        let len: u8 = len.parse().ok()?;
        match address.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) if len <= 32 => {
                let network = u32::from(v4);
                (network & !mask32(len) == 0).then_some(Block::V4 { network, len })
            }
            IpAddr::V6(v6) if len <= 128 => {
                let network = u128::from(v6);
                (network & !mask128(len) == 0).then_some(Block::V6 { network, len })
            }
            _ => None,
        }
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self, address) {
            (Block::V4 { network, len }, IpAddr::V4(v4)) => {
                u32::from(v4) & mask32(*len) == *network
            }
            (Block::V6 { network, len }, IpAddr::V6(v6)) => {
                u128::from(v6) & mask128(*len) == *network
            }
            _ => false,
        }
    }

    /// Whether every address of `other` is inside this block.
    pub fn covers(&self, other: &Block) -> bool {
        match (self, other) {
            (
                Block::V4 { len, .. },
                Block::V4 {
                    network,
                    len: inner,
                },
            ) => inner >= len && self.contains(IpAddr::V4(Ipv4Addr::from(*network))),
            (
                Block::V6 { len, .. },
                Block::V6 {
                    network,
                    len: inner,
                },
            ) => inner >= len && self.contains(IpAddr::V6(Ipv6Addr::from(*network))),
            _ => false,
        }
    }

    /// The first and last address of the block.
    pub fn bounds(&self) -> (IpAddr, IpAddr) {
        match *self {
            Block::V4 { network, len } => (
                IpAddr::V4(Ipv4Addr::from(network)),
                IpAddr::V4(Ipv4Addr::from(network | !mask32(len))),
            ),
            Block::V6 { network, len } => (
                IpAddr::V6(Ipv6Addr::from(network)),
                IpAddr::V6(Ipv6Addr::from(network | !mask128(len))),
            ),
        }
    }
}

fn mask32(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    }
}

fn mask128(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    }
}

/// One entry of the compiled table.
#[derive(Debug, Clone, Copy)]
pub struct Refused {
    pub prefix: &'static str,
    pub name: &'static str,
    pub block: Block,
}

/// The whole table, parsed once. A row that fails to parse is a build
/// mistake caught by the first test that touches the table.
pub fn table() -> &'static [Refused] {
    static TABLE: OnceLock<Vec<Refused>> = OnceLock::new();
    TABLE.get_or_init(|| {
        V4.iter()
            .chain(V6)
            .map(|&(prefix, name)| Refused {
                prefix,
                name,
                block: Block::parse(prefix)
                    .unwrap_or_else(|| panic!("special-purpose table row {prefix} is malformed")),
            })
            .collect()
    })
}

/// IPv6 global unicast: the only IPv6 space an upstream may be in.
const GLOBAL_UNICAST: Block = Block::V6 {
    network: 0x2000 << 112,
    len: 3,
};

/// Why `address` may not be connected to, or `None` when it is globally
/// routable. The most specific named block wins, so an embedding form is
/// named as one even where a wider block also covers it.
pub fn refusal(address: IpAddr) -> Option<String> {
    let named = table()
        .iter()
        .filter(|row| row.block.contains(address))
        .max_by_key(|row| match row.block {
            Block::V4 { len, .. } | Block::V6 { len, .. } => len,
        });
    if let Some(row) = named {
        return Some(format!(
            "{address} is in {} ({}), which is not globally routable",
            row.prefix, row.name
        ));
    }
    if address.is_ipv6() && !GLOBAL_UNICAST.contains(address) {
        return Some(format!(
            "{address} is outside 2000::/3, the only IPv6 space that is global unicast"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// The start, middle, and end address of a block.
    fn samples(block: &Block) -> [IpAddr; 3] {
        let (start, end) = block.bounds();
        let middle = match (start, end) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let (a, b) = (u32::from(a), u32::from(b));
                IpAddr::V4(Ipv4Addr::from(a + (b - a) / 2))
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let (a, b) = (u128::from(a), u128::from(b));
                IpAddr::V6(Ipv6Addr::from(a + (b - a) / 2))
            }
            _ => unreachable!(),
        };
        [start, middle, end]
    }

    /// The case name the design's test plan uses: `refuses_<prefix>_<name>`.
    fn case_name(row: &Refused) -> String {
        let mut name = String::from("refuses_");
        for c in row.prefix.chars().chain(['_']).chain(row.name.chars()) {
            if c.is_ascii_alphanumeric() {
                name.push(c.to_ascii_lowercase());
            } else if !name.ends_with('_') {
                name.push('_');
            }
        }
        name.trim_end_matches('_').to_string()
    }

    #[test]
    fn proxy_refuses_every_iana_special_purpose_range() {
        let mut cases = 0;
        for row in table() {
            let case = case_name(row);
            for sample in samples(&row.block) {
                let reason =
                    refusal(sample).unwrap_or_else(|| panic!("{case}: {sample} was accepted"));
                assert!(reason.contains("not globally routable"), "{case}: {reason}");
                cases += 1;
            }
        }
        assert_eq!(cases, 3 * (V4.len() + V6.len()));
        // The names the test plan calls out.
        let names: Vec<String> = table().iter().map(case_name).collect();
        for expected in [
            "refuses_100_64_0_0_10_shared_address_space_cgnat",
            "refuses_198_18_0_0_15_benchmarking",
            "refuses_fc00_7_unique_local",
        ] {
            assert!(names.iter().any(|name| name == expected), "{expected}");
        }
        // The embedding forms, each named as the embedding it is.
        for (embedded, form) in [
            ("::ffff:8.8.8.8", "IPv4-mapped"),
            ("::ffff:127.0.0.1", "IPv4-mapped"),
            ("::8.8.8.8", "IPv4-compatible"),
            ("64:ff9b::808:808", "NAT64"),
            ("64:ff9b:1::a00:1", "local-use NAT64"),
            ("2002:808:808::1", "6to4"),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "Teredo"),
        ] {
            let reason = refusal(addr(embedded)).unwrap();
            assert!(reason.contains(form), "{embedded}: {reason}");
        }
        // Outside 2000::/3 without a named row.
        let reason = refusal(addr("4000::1")).unwrap();
        assert!(reason.contains("outside 2000::/3"), "{reason}");
        let reason = refusal(addr("fec0::1")).unwrap();
        assert!(reason.contains("outside 2000::/3"), "{reason}");
    }

    #[test]
    fn proxy_accepts_a_global_address_next_to_each_refused_range() {
        let refused = |address: IpAddr| refusal(address).is_some();
        let mut checked = 0;
        for row in table() {
            let (start, end) = row.block.bounds();
            let neighbours = match (start, end) {
                (IpAddr::V4(a), IpAddr::V4(b)) => [
                    u32::from(a)
                        .checked_sub(1)
                        .map(|n| IpAddr::V4(Ipv4Addr::from(n))),
                    u32::from(b)
                        .checked_add(1)
                        .map(|n| IpAddr::V4(Ipv4Addr::from(n))),
                ],
                (IpAddr::V6(a), IpAddr::V6(b)) => [
                    u128::from(a)
                        .checked_sub(1)
                        .map(|n| IpAddr::V6(Ipv6Addr::from(n))),
                    u128::from(b)
                        .checked_add(1)
                        .map(|n| IpAddr::V6(Ipv6Addr::from(n))),
                ],
                _ => unreachable!(),
            };
            for neighbour in neighbours.into_iter().flatten() {
                // A neighbour inside another refused block, or outside IPv6
                // global unicast, is not "next to" this one in global space.
                let elsewhere = table()
                    .iter()
                    .any(|other| other.prefix != row.prefix && other.block.contains(neighbour));
                let v6_non_global = neighbour.is_ipv6() && !GLOBAL_UNICAST.contains(neighbour);
                if elsewhere || v6_non_global {
                    continue;
                }
                assert!(
                    !refused(neighbour),
                    "{neighbour}, next to {}, was refused",
                    row.prefix
                );
                checked += 1;
            }
        }
        // Every IPv4 row has at least one global neighbour, and the IPv6
        // rows inside 2000::/3 contribute theirs.
        assert!(checked >= 30, "only {checked} neighbours were checked");
        for global in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2a00:1450::1"] {
            assert_eq!(refusal(addr(global)), None, "{global}");
        }
    }

    /// Split one CSV record set into rows of fields, honoring quotes (the
    /// registry's RFC column holds line breaks inside quotes).
    fn csv_rows(text: &str) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut row = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            match (c, quoted) {
                ('"', true) if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                ('"', _) => quoted = !quoted,
                (',', false) => row.push(std::mem::take(&mut field)),
                ('\n', false) => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                ('\r', false) => {}
                (c, _) => field.push(c),
            }
        }
        if !field.is_empty() || !row.is_empty() {
            row.push(field);
            rows.push(row);
        }
        rows
    }

    /// Every block the pinned registry lists, with its "Globally Reachable"
    /// cell. A cell holding several prefixes yields one block each; footnote
    /// markers (`[2]`) are dropped.
    fn registry_blocks(file: &str) -> Vec<(Block, String, String)> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/iana")
            .join(file);
        let text = std::fs::read_to_string(&path).unwrap();
        let rows = csv_rows(&text);
        let header = &rows[0];
        let column = |name: &str| header.iter().position(|h| h == name).unwrap();
        let (block_at, reach_at) = (column("Address Block"), column("Globally Reachable"));
        let mut blocks = Vec::new();
        for row in &rows[1..] {
            let reach = row[reach_at].split('[').next().unwrap().trim().to_string();
            for prefix in row[block_at].split(',') {
                let prefix = prefix.split('[').next().unwrap().trim();
                let block = Block::parse(prefix)
                    .unwrap_or_else(|| panic!("{file}: unparseable block {prefix:?}"));
                blocks.push((block, prefix.to_string(), reach.clone()));
            }
        }
        assert!(
            blocks.len() > 15,
            "{file} parsed to only {} blocks",
            blocks.len()
        );
        blocks
    }

    #[test]
    fn iana_special_purpose_table_matches_the_pinned_registry() {
        let registry: Vec<(Block, String, String)> =
            registry_blocks("iana-ipv4-special-registry-1.csv")
                .into_iter()
                .chain(registry_blocks("iana-ipv6-special-registry-1.csv"))
                .collect();
        // 1. Every block the registry does not mark globally reachable
        //    (False, N/A, or blank for a deprecated row) is refused whole.
        for (block, prefix, reach) in &registry {
            if reach == "True" {
                continue;
            }
            assert!(
                table().iter().any(|row| row.block.covers(block)),
                "registry block {prefix} (globally reachable: {reach:?}) is not refused"
            );
        }
        // 2. Every table row is a registry block, or one of the deliberate
        //    extras the module documentation names.
        const EXTRAS: &[&str] = &["224.0.0.0/4", "::/96", "ff00::/8"];
        for row in table() {
            let listed = registry.iter().any(|(block, _, _)| *block == row.block);
            assert!(
                listed || EXTRAS.contains(&row.prefix),
                "{} is neither a registry block nor a documented extra",
                row.prefix
            );
        }
        // 3. The registry blocks marked globally reachable that the table
        //    still refuses are exactly the documented ones.
        let mut refused_anyway: Vec<&str> = registry
            .iter()
            .filter(|(block, _, reach)| {
                reach == "True" && table().iter().any(|row| row.block == *block)
            })
            .map(|(_, prefix, _)| prefix.as_str())
            .collect();
        refused_anyway.sort_unstable();
        assert_eq!(
            refused_anyway,
            [
                "192.175.48.0/24",
                "192.31.196.0/24",
                "192.52.193.0/24",
                "64:ff9b::/96"
            ]
        );
    }
}
