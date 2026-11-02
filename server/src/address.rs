//! The overlay address space and stable, lowest-free address assignment.

use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasher,
    net::Ipv4Addr,
};

use crate::{
    error::{Error, Result},
    verifier::Verifier,
};

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

/// Assigns one address to every account in `verifiers`.
///
/// Stored addresses of surviving accounts are kept when they are still
/// assignable and not claimed twice. Every other account gets the lowest free
/// assignable address starting at [`FIRST_ADDRESS`], no higher than `last`.
///
/// # Errors
/// Returns `Error::AddressExhausted` when no free address exists at or below `last`.
pub fn assign<S: BuildHasher>(
    verifiers: &[Verifier],
    stored: &HashMap<Verifier, Ipv4Addr, S>,
    last: Ipv4Addr,
) -> Result<HashMap<Verifier, Ipv4Addr>> {
    let mut next = HashMap::with_capacity(verifiers.len());
    let mut used = HashSet::with_capacity(verifiers.len());
    for verifier in verifiers {
        let Some(&address) = stored.get(verifier) else {
            continue;
        };
        if assignable(address) && used.insert(address) {
            next.insert(*verifier, address);
        }
    }
    let mut cursor = u32::from(FIRST_ADDRESS);
    let last = u32::from(last);
    for verifier in verifiers {
        if next.contains_key(verifier) {
            continue;
        }
        let address = next_free(&mut cursor, last, &used)?;
        used.insert(address);
        next.insert(*verifier, address);
    }
    Ok(next)
}

fn next_free(cursor: &mut u32, last: u32, used: &HashSet<Ipv4Addr>) -> Result<Ipv4Addr> {
    while *cursor <= last {
        let candidate = Ipv4Addr::from(*cursor);
        *cursor += 1;
        if assignable(candidate) && !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::AddressExhausted)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::Ipv4Addr};

    use super::{LAST_ADDRESS, assign, assignable};
    use crate::{error::Error, verifier::Verifier};

    fn account(byte: u8) -> Verifier {
        Verifier::from_digest([byte; 32])
    }

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
    fn new_accounts_get_lowest_free_addresses() {
        let verifiers = [account(1), account(2), account(3)];
        let assigned = assign(&verifiers, &HashMap::new(), LAST_ADDRESS);
        let got: Vec<Option<Ipv4Addr>> = verifiers
            .iter()
            .map(|v| assigned.as_ref().ok().and_then(|map| map.get(v).copied()))
            .collect();
        assert_eq!(
            got,
            vec![
                Some(ip("10.77.0.1")),
                Some(ip("10.77.0.2")),
                Some(ip("10.77.0.3"))
            ]
        );
    }

    #[test]
    fn survivors_keep_addresses_across_reordering_and_removal() {
        let (a, b, c, d) = (account(1), account(2), account(3), account(4));
        let first = assign(&[a, b, c], &HashMap::new(), LAST_ADDRESS).unwrap_or_default();
        let reordered = assign(&[c, b, a], &first, LAST_ADDRESS).unwrap_or_default();
        assert_eq!(reordered, first, "reordering must not renumber accounts");

        let after_removal = assign(&[a, c], &first, LAST_ADDRESS).unwrap_or_default();
        assert_eq!(after_removal.get(&a), Some(&ip("10.77.0.1")));
        assert_eq!(
            after_removal.get(&c),
            Some(&ip("10.77.0.3")),
            "survivor keeps its address"
        );

        let with_new = assign(&[a, c, d], &after_removal, LAST_ADDRESS).unwrap_or_default();
        assert_eq!(
            with_new.get(&d),
            Some(&ip("10.77.0.2")),
            "freed address is reused"
        );
    }

    #[test]
    fn duplicate_or_invalid_stored_addresses_are_renumbered() {
        let (a, b) = (account(1), account(2));
        let mut stored = HashMap::new();
        stored.insert(a, ip("10.77.0.5"));
        stored.insert(b, ip("10.77.0.5"));
        let assigned = assign(&[a, b], &stored, LAST_ADDRESS).unwrap_or_default();
        assert_eq!(assigned.get(&a), Some(&ip("10.77.0.5")));
        assert_eq!(
            assigned.get(&b),
            Some(&ip("10.77.0.1")),
            "second claimant is renumbered"
        );
    }

    #[test]
    fn exhausted_space_is_an_error() {
        let verifiers = [account(1), account(2), account(3)];
        let result = assign(&verifiers, &HashMap::new(), ip("10.77.0.2"));
        assert!(
            matches!(result, Err(Error::AddressExhausted)),
            "only two addresses fit"
        );
    }
}
