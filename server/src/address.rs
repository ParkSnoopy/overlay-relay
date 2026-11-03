//! The overlay address space and lowest-free address selection.

use std::{collections::HashSet, hash::BuildHasher, net::Ipv4Addr};

use crate::error::{Error, Result};

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
