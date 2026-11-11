//! The overlay address space and lowest-free address selection.

use std::{collections::HashSet, hash::BuildHasher, net::Ipv4Addr};

use crate::error::{Error, Result};

/// A canonical `IPv4` subnet wholly inside RFC 1918 private space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSpace {
    network: u32,
    bits: u8,
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self {
            network: u32::from(Ipv4Addr::new(10, 77, 0, 0)),
            bits: 16,
        }
    }
}

impl std::str::FromStr for AddressSpace {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        let invalid = || {
            Error::Config("overlay range must be a canonical RFC 1918 IPv4 subnet, /8 through /30")
        };
        let (ip, bits) = value.split_once('/').ok_or_else(invalid)?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| invalid())?;
        let bits: u8 = bits.parse().map_err(|_| invalid())?;
        let minimum = match ip.octets() {
            [10, ..] => 8,
            [172, 16..=31, ..] => 12,
            [192, 168, ..] => 16,
            _ => return Err(invalid()),
        };
        if !(minimum..=30).contains(&bits) {
            return Err(invalid());
        }
        let network = u32::from(ip);
        if network & (!0_u32 >> bits) != 0 {
            return Err(invalid());
        }
        let space = Self { network, bits };
        if space.to_string() != value {
            return Err(invalid());
        }
        Ok(space)
    }
}

impl std::fmt::Display for AddressSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.network), self.bits)
    }
}

impl AddressSpace {
    /// Whether this is a host address, excluding network and broadcast.
    #[must_use]
    pub fn assignable(self, address: Ipv4Addr) -> bool {
        let address = u32::from(address);
        address > self.network && address < self.network + (!0_u32 >> self.bits)
    }

    /// Selects the lowest unused host address without allocating the full range.
    ///
    /// # Errors
    /// Returns `Error::AddressExhausted` when all usable hosts are assigned.
    pub fn lowest_free<S: BuildHasher>(self, used: &HashSet<Ipv4Addr, S>) -> Result<Ipv4Addr> {
        let mut cursor = self.network + 1;
        let last = self.network + (!0_u32 >> self.bits);
        while cursor < last {
            let candidate = Ipv4Addr::from(cursor);
            if !used.contains(&candidate) {
                return Ok(candidate);
            }
            cursor += 1;
        }
        Err(Error::AddressExhausted)
    }
}

/// The first address handed to an account.
pub const FIRST_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);

/// The last address of the overlay space, 10.77.255.255.
pub const LAST_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 77, 255, 255);

/// Reports whether `address` may be handed to an account: inside 10.77.0.0/16,
/// and neither the network address 10.77.0.0 nor the broadcast address 10.77.255.255.
#[must_use]
pub const fn assignable(address: Ipv4Addr) -> bool {
    let [first, second, third, fourth] = address.octets();
    first == 10 && second == 77 && !(third == 0 && fourth == 0) && !(third == 255 && fourth == 255)
}

/// Returns the lowest assignable address at or below `last` that is not in `used`.
///
/// # Errors
/// Returns `Error::AddressExhausted` when no free address exists at or below `last`.
pub fn lowest_free<S: BuildHasher>(
    used: &HashSet<Ipv4Addr, S>,
    last: Ipv4Addr,
) -> Result<Ipv4Addr> {
    let mut cursor = u32::from(FIRST_ADDRESS);
    let last = u32::from(last);
    while cursor <= last {
        let candidate = Ipv4Addr::from(cursor);
        cursor += 1;
        if assignable(candidate) && !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::AddressExhausted)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::Ipv4Addr};

    use super::{LAST_ADDRESS, assignable, lowest_free};
    use crate::error::Error;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    #[test]
    fn configured_ranges_are_wholly_inside_rfc1918_space() {
        for cidr in [
            "10.0.0.0/8",
            "10.77.0.0/16",
            "172.16.0.0/12",
            "172.31.255.252/30",
            "192.168.0.0/16",
            "192.168.77.0/30",
        ] {
            assert!(cidr.parse::<super::AddressSpace>().is_ok(), "{cidr}");
        }
        for cidr in [
            "10.77.0.1/16",
            "0.0.0.0/8",
            "127.0.0.0/8",
            "224.0.0.0/8",
            "10.0.0.0/7",
            "10.77.0.0/31",
            "::/16",
            "176.77.0.0/16",
            "172.0.0.0/8",
            "172.16.0.0/11",
            "172.15.0.0/16",
            "172.32.0.0/16",
            "192.168.0.0/15",
            "192.169.0.0/16",
            "100.64.0.0/10",
            "169.254.0.0/16",
            "10.0.0.0/08",
            "10.0.0.0/+8",
            "10.01.0.0/16",
            "10.0.0.1/32",
            "192.168.100.1/24",
            "192.168.100.0/24 ",
            "",
        ] {
            assert!(cidr.parse::<super::AddressSpace>().is_err(), "{cidr}");
        }
    }

    #[test]
    fn network_and_broadcast_are_not_assignable() {
        assert!(assignable(ip("10.77.0.1")));
        assert!(assignable(ip("10.77.1.0")));
        assert!(!assignable(ip("10.77.0.0")), "network address");
        assert!(!assignable(ip("10.77.255.255")), "broadcast address");
        assert!(!assignable(ip("10.78.0.1")), "outside the /16");
        assert!(!assignable(ip("10.76.0.1")), "outside the /16");
    }

    #[test]
    fn lowest_free_skips_used_addresses() {
        let used: HashSet<Ipv4Addr> = [ip("10.77.0.1"), ip("10.77.0.3")].into_iter().collect();
        assert_eq!(lowest_free(&used, LAST_ADDRESS).ok(), Some(ip("10.77.0.2")));
        assert_eq!(
            lowest_free(&HashSet::new(), LAST_ADDRESS).ok(),
            Some(ip("10.77.0.1"))
        );
    }

    #[test]
    fn exhausted_space_is_an_error() {
        let used: HashSet<Ipv4Addr> = [ip("10.77.0.1"), ip("10.77.0.2")].into_iter().collect();
        assert!(
            matches!(
                lowest_free(&used, ip("10.77.0.2")),
                Err(Error::AddressExhausted)
            ),
            "only two addresses fit"
        );
    }
}
