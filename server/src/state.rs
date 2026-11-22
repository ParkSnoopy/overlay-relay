//! Hub state: known identities, live control streams, pending open requests
//! and active flows. Callers hold the state lock only for these synchronous
//! operations and never across an await point.

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use tokio::{net::TcpStream, sync::oneshot};

use crate::{
    address::AddressSpace,
    assignments::Record,
    control::ControlHandle,
    dhcp::Dhcp,
    protocol::{MAX_ACCOUNTS, MAX_FLOWS_PER_ACCOUNT, MAX_PENDING_PER_ACCOUNT, Offer, Peer},
    verifier::Verifier,
};

/// Seconds a stored last-seen time may lag before an authentication rewrites it.
const SEEN_GRANULARITY: u64 = 3600;

/// An authenticated account, as seen by one stream.
#[derive(Debug, Clone)]
pub struct Requester {
    /// Authenticated room capability for this stream, never a public room label.
    pub room: String,
    /// Display name of the private room, empty in the public room.
    pub room_name: String,
    /// The account's verifier.
    pub verifier: Verifier,
    /// The account's display name, sent only in its own control reply.
    pub name: String,
    /// The account's overlay address.
    pub ip: Ipv4Addr,
}

/// What the destination hands to a waiting open request: its stream and its offer.
#[derive(Debug)]
pub struct Accepted {
    /// The accept stream.
    pub stream: TcpStream,
    /// What the destination offers for the flow.
    pub offer: Offer,
}

/// An open request waiting for its destination to accept.
#[derive(Debug)]
pub struct Pending {
    /// Room in which the request was admitted.
    pub room: String,
    /// Verifier of the account that asked.
    pub requester: Verifier,
    /// Verifier of the account that must accept.
    pub destination: Verifier,
    /// Hands the acceptor's stream and offer to the waiting open request.
    pub accept: oneshot::Sender<Accepted>,
}

#[derive(Debug)]
struct FlowEntry {
    accounts: [Verifier; 2],
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    ip: Ipv4Addr,
    seen: u64,
}

impl Entry {
    fn wire_name(&self, verifier: &Verifier) -> String {
        advertised_name(&self.name, verifier)
    }
}

/// Returns the device's default display name when none is advertised.
pub fn advertised_name(name: &str, verifier: &Verifier) -> String {
    if name.is_empty() {
        let id = verifier.to_hex();
        format!("peer-{}", id.get(..8).unwrap_or(&id))
    } else {
        name.to_owned()
    }
}

/// The hub's mutable state.
#[derive(Debug, Default)]
pub struct State {
    dhcp: Dhcp,
    reservations: HashMap<Verifier, Ipv4Addr>,
    reserved_ips: HashSet<Ipv4Addr>,
    accounts: HashMap<Verifier, Entry>,
    by_ip: HashMap<Ipv4Addr, Verifier>,
    controls: HashMap<Verifier, ControlHandle>,
    pending: HashMap<String, Pending>,
    flows: HashMap<u64, FlowEntry>,
    serial: u64,
    dirty: bool,
}

impl State {
    /// Builds the state from persisted identities. Addresses that repeat or
    /// are not assignable are dropped, so the identity receives a new one.
    #[must_use]
    pub fn load(records: &HashMap<Verifier, Record>) -> Self {
        Self::load_in(records, AddressSpace::default())
    }

    /// Loads only assignments belonging to the selected range.
    #[must_use]
    pub fn load_in(records: &HashMap<Verifier, Record>, address_space: AddressSpace) -> Self {
        Self::load_dhcp(records, address_space, Dhcp::for_space(address_space))
    }

    /// Load assignments against an already validated administrative DHCP policy.
    #[must_use]
    pub fn load_dhcp(
        records: &HashMap<Verifier, Record>,
        address_space: AddressSpace,
        dhcp: Dhcp,
    ) -> Self {
        let reservations: HashMap<Verifier, Ipv4Addr> = dhcp
            .bindings
            .iter()
            .filter_map(|binding| binding.verifier().map(|key| (key, binding.ip)))
            .collect();
        let reserved_ips: HashSet<Ipv4Addr> = reservations.values().copied().collect();
        let mut state = Self {
            dhcp,
            reservations,
            reserved_ips,
            ..Self::default()
        };
        for (verifier, record) in records {
            let reserved = state.reservations.get(verifier);
            let ip = reserved.copied().unwrap_or(record.ip);
            let eligible = reserved.is_some()
                || (ip >= state.dhcp.start
                    && ip <= state.dhcp.end
                    && !state.reserved_ips.contains(&ip));
            state.dirty |= ip != record.ip;
            if !eligible || !address_space.assignable(ip) || state.by_ip.contains_key(&ip) {
                state.dirty = true;
                continue;
            }
            state.by_ip.insert(ip, *verifier);
            state.accounts.insert(
                *verifier,
                Entry {
                    name: record.name.clone(),
                    ip,
                    seen: record.seen,
                },
            );
        }
        state
    }

    /// Returns a fresh identifier for controls and flows.
    pub const fn next_serial(&mut self) -> u64 {
        self.serial += 1;
        self.serial
    }

    /// Returns the persisted form when it changed since the last call.
    pub fn take_dirty(&mut self) -> Option<HashMap<Verifier, Record>> {
        if !self.dirty {
            return None;
        }
        self.dirty = false;
        Some(
            self.accounts
                .iter()
                .map(|(verifier, entry)| {
                    (
                        *verifier,
                        Record {
                            ip: entry.ip,
                            seen: entry.seen,
                            name: entry.name.clone(),
                        },
                    )
                })
                .collect(),
        )
    }

    /// Marks the persisted form stale again after a failed write.
    pub const fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Resolves an identity whose key was proven. A new identity gets the
    /// lowest free address; at capacity the least recently seen idle identity
    /// gives up its address. Returns `None` when no identity can be evicted.
    pub fn identify(&mut self, verifier: Verifier, now: u64) -> Option<Requester> {
        if self.dhcp.lease_seconds != 0 {
            let expired: Vec<Verifier> = self
                .accounts
                .iter()
                .filter(|(key, entry)| {
                    now.saturating_sub(entry.seen) >= self.dhcp.lease_seconds
                        && !self.reservations.contains_key(key)
                        && !self.controls.contains_key(key)
                        && self.flow_count(key) == 0
                })
                .map(|(key, _)| *key)
                .collect();
            for key in expired {
                self.remove_idle(key);
            }
        }
        let granularity = if self.dhcp.lease_seconds == 0 {
            SEEN_GRANULARITY
        } else {
            SEEN_GRANULARITY.min(self.dhcp.lease_seconds / 2)
        };
        if let Some(entry) = self.accounts.get_mut(&verifier) {
            if now.saturating_sub(entry.seen) >= granularity {
                entry.seen = now;
                self.dirty = true;
            }
        } else {
            if self.accounts.len() >= MAX_ACCOUNTS {
                self.evict_idle(now)?;
            }
            let ip = match self.reservations.get(&verifier) {
                Some(ip) => *ip,
                None => {
                    if let Some(ip) = self.lowest_dynamic() {
                        ip
                    } else {
                        self.evict_idle(now)?;
                        self.lowest_dynamic()?
                    }
                }
            };
            self.by_ip.insert(ip, verifier);
            self.accounts.insert(
                verifier,
                Entry {
                    name: String::new(),
                    ip,
                    seen: now,
                },
            );
            self.dirty = true;
        }
        let entry = self.accounts.get(&verifier)?;
        Some(Requester {
            room: String::new(),
            room_name: String::new(),
            verifier,
            name: entry.wire_name(&verifier),
            ip: entry.ip,
        })
    }

    /// Records that `verifier` was just active, for eviction order.
    pub fn touch(&mut self, verifier: &Verifier, now: u64) {
        if let Some(entry) = self.accounts.get_mut(verifier) {
            entry.seen = now;
            self.dirty = true;
        }
    }

    /// Removes the idle identity seen longest ago. Identities with a control
    /// stream or an active flow are never removed.
    fn lowest_dynamic(&self) -> Option<Ipv4Addr> {
        (u32::from(self.dhcp.start)..=u32::from(self.dhcp.end))
            .map(Ipv4Addr::from)
            .find(|ip| !self.by_ip.contains_key(ip) && !self.reserved_ips.contains(ip))
    }

    fn evict_idle(&mut self, now: u64) -> Option<()> {
        let oldest = self
            .accounts
            .iter()
            .filter(|(verifier, entry)| {
                !self.reservations.contains_key(verifier)
                    && !self.controls.contains_key(verifier)
                    && self.flow_count(verifier) == 0
                    && (self.dhcp.lease_seconds == 0
                        || now.saturating_sub(entry.seen) >= self.dhcp.lease_seconds)
            })
            .min_by_key(|(_, entry)| entry.seen)
            .map(|(verifier, _)| *verifier)?;
        self.remove_idle(oldest);
        Some(())
    }

    fn remove_idle(&mut self, oldest: Verifier) {
        if let Some(entry) = self.accounts.remove(&oldest) {
            self.by_ip.remove(&entry.ip);
        }
        self.pending
            .retain(|_, pending| pending.requester != oldest && pending.destination != oldest);
        self.dirty = true;
    }

    /// The overlay address of a known identity.
    #[must_use]
    pub fn address_of(&self, verifier: &Verifier) -> Option<Ipv4Addr> {
        self.accounts.get(verifier).map(|entry| entry.ip)
    }

    pub(crate) fn lookup_name(
        &self,
        requester: &Requester,
        generation: u64,
        owner: &Verifier,
    ) -> Option<Ipv4Addr> {
        let from = self.controls.get(&requester.verifier)?;
        let to = self.controls.get(owner)?;
        let ip = self.address_of(owner)?;
        (from.generation == generation
            && !from.close.is_cancelled()
            && from.room == requester.room
            && to.room == from.room
            && !to.close.is_cancelled()
            && self.by_ip.get(&ip) == Some(owner))
        .then_some(ip)
    }

    /// Updates the authenticated device's advertised display name.
    pub fn set_name(&mut self, verifier: &Verifier, name: &str) -> Option<String> {
        let entry = self.accounts.get_mut(verifier)?;
        if entry.name != name {
            entry.name.clear();
            entry.name.push_str(name);
            self.dirty = true;
        }
        Some(entry.wire_name(verifier))
    }

    /// Lists every other broadcasting account, sorted by overlay address.
    #[must_use]
    pub fn snapshot(&self, self_verifier: Verifier) -> Vec<Peer> {
        let mut listed: Vec<(Ipv4Addr, Peer)> = Vec::new();
        let Some(own) = self.controls.get(&self_verifier) else {
            return Vec::new();
        };
        for verifier in self.controls.keys() {
            if *verifier == self_verifier
                || self
                    .controls
                    .get(verifier)
                    .is_none_or(|control| control.room != own.room)
            {
                continue;
            }
            if let Some(entry) = self.accounts.get(verifier) {
                let peer = Peer {
                    id: verifier.to_hex(),
                    ip: entry.ip.to_string(),
                    name: entry.wire_name(verifier),
                };
                listed.push((entry.ip, peer));
            }
        }
        listed.sort_by_key(|(ip, _)| *ip);
        listed.into_iter().map(|(_, peer)| peer).collect()
    }

    /// Marks every control stream dirty so each one sends a fresh snapshot.
    pub fn notify_all(&self) {
        for control in self.controls.values() {
            control.dirty.notify_one();
        }
    }

    /// Registers a control stream and returns the one it replaces, if any.
    pub fn register_control(
        &mut self,
        verifier: Verifier,
        handle: ControlHandle,
    ) -> Option<ControlHandle> {
        self.controls.insert(verifier, handle)
    }

    /// Removes a control stream if it is still the registered one.
    pub fn unregister_control(&mut self, verifier: Verifier, generation: u64) {
        let current = self
            .controls
            .get(&verifier)
            .is_some_and(|control| control.generation == generation);
        if current {
            self.controls.remove(&verifier);
            self.notify_all();
        }
    }

    /// Records an open request if every admission rule passes, and returns the
    /// destination verifier with a handle to its control stream. Any failed
    /// rule yields `None`, and the caller reports the same error for all of them.
    pub fn admit_request(
        &mut self,
        requester: &Requester,
        destination: Ipv4Addr,
        id: &str,
        accept: oneshot::Sender<Accepted>,
    ) -> Option<(Verifier, ControlHandle)> {
        let dest = *self.by_ip.get(&destination)?;
        let allowed = dest != requester.verifier
            && self
                .controls
                .get(&requester.verifier)
                .is_some_and(|control| control.room == requester.room)
            && self
                .controls
                .get(&dest)
                .is_some_and(|control| control.room == requester.room)
            && self.flow_count(&requester.verifier) < MAX_FLOWS_PER_ACCOUNT
            && self.flow_count(&dest) < MAX_FLOWS_PER_ACCOUNT
            && self.pending_count(&dest) < MAX_PENDING_PER_ACCOUNT;
        if !allowed {
            return None;
        }
        let target = self.controls.get(&dest)?.clone();
        self.pending.insert(
            id.to_owned(),
            Pending {
                room: requester.room.clone(),
                requester: requester.verifier,
                destination: dest,
                accept,
            },
        );
        Some((dest, target))
    }

    /// Removes and returns the pending request `id` if `acceptor` is its destination.
    pub fn claim_pending(&mut self, id: &str, acceptor: &Verifier, room: &str) -> Option<Pending> {
        let owned = self.pending.get(id).is_some_and(|pending| {
            pending.destination == *acceptor
                && pending.room == room
                && self
                    .controls
                    .get(acceptor)
                    .is_some_and(|control| control.room == room)
                && self
                    .controls
                    .get(&pending.requester)
                    .is_some_and(|control| control.room == room)
        });
        if owned { self.pending.remove(id) } else { None }
    }

    /// Removes the pending request `id` regardless of its destination.
    pub fn remove_pending(&mut self, id: &str) -> Option<Pending> {
        self.pending.remove(id)
    }

    /// Registers an active flow between two accounts. Returns `None` when an
    /// account is unknown or already holds its flow limit.
    pub fn open_flow(&mut self, accounts: [Verifier; 2]) -> Option<u64> {
        let known = accounts
            .iter()
            .all(|verifier| self.accounts.contains_key(verifier));
        let capacity = accounts
            .iter()
            .all(|verifier| self.flow_count(verifier) < MAX_FLOWS_PER_ACCOUNT);
        if !(known && capacity) {
            return None;
        }
        let id = self.next_serial();
        self.flows.insert(id, FlowEntry { accounts });
        Some(id)
    }

    /// Forgets a flow once its relay has ended.
    pub fn remove_flow(&mut self, flow: u64) {
        if let Some(entry) = self.flows.remove(&flow) {
            let now = crate::unix_now();
            for verifier in entry.accounts {
                self.touch(&verifier, now);
            }
        }
    }

    /// Number of active flows that involve `verifier`.
    #[must_use]
    pub fn flow_count(&self, verifier: &Verifier) -> usize {
        self.flows
            .values()
            .filter(|flow| flow.accounts.contains(verifier))
            .count()
    }

    /// Number of pending open requests addressed to `dest`.
    #[must_use]
    pub fn pending_count(&self, dest: &Verifier) -> usize {
        self.pending
            .values()
            .filter(|pending| pending.destination == *dest)
            .count()
    }
}


#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::Ipv4Addr};

    use super::State;
    use crate::{
        assignments::Record,
        protocol::{MAX_ACCOUNTS, MAX_FLOWS_PER_ACCOUNT},
        verifier::Verifier,
    };

    fn account(index: u32) -> Verifier {
        let mut digest = [0_u8; 32];
        digest[..4].copy_from_slice(&index.to_be_bytes());
        Verifier::from_digest(digest)
    }

    #[test]
    fn dhcp_lease_exhaustion_and_expiry() {
        let space = crate::AddressSpace::default();
        let mut policy = crate::dhcp::Dhcp::for_space(space);
        policy.end = Ipv4Addr::new(10, 77, 0, 2);
        policy.lease_seconds = 60;
        let mut state = State::load_dhcp(&HashMap::new(), space, policy);
        assert!(state.identify(account(1), 100).is_some());
        assert!(state.identify(account(2), 100).is_some());
        assert_ne!(state.address_of(&account(1)), state.address_of(&account(2)));
        assert!(state.identify(account(3), 159).is_none());
        assert!(state.identify(account(3), 160).is_some());
        assert!(state.identify(account(4), 160).is_some());
        assert!(state.identify(account(5), 160).is_none());
    }

    #[test]
    fn dhcp_active_flows_keep_expired_addresses() {
        let space = crate::AddressSpace::default();
        let mut policy = crate::dhcp::Dhcp::for_space(space);
        policy.end = Ipv4Addr::new(10, 77, 0, 2);
        policy.lease_seconds = 60;
        let mut state = State::load_dhcp(&HashMap::new(), space, policy);
        assert!(state.identify(account(1), 100).is_some());
        assert!(state.identify(account(2), 100).is_some());
        assert!(state.open_flow([account(1), account(2)]).is_some());
        assert!(state.identify(account(3), 1000).is_none());
    }

    fn address(state: &State, verifier: &Verifier) -> Option<Ipv4Addr> {
        state.address_of(verifier)
    }

    #[test]
    fn flow_limit_applies_per_account() {
        let (a, b) = (account(1), account(2));
        let mut state = State::default();
        assert!(state.identify(a, 0).is_some());
        assert!(state.identify(b, 0).is_some());
        for index in 0..MAX_FLOWS_PER_ACCOUNT {
            assert!(
                state.open_flow([a, b]).is_some(),
                "flow {index} must be admitted"
            );
        }
        assert!(
            state.open_flow([a, b]).is_none(),
            "flow above the per-account limit must be refused"
        );
    }

    #[test]
    fn identities_get_lowest_free_addresses_and_keep_them() {
        let mut state = State::default();
        let first = state.identify(account(1), 0).map(|found| found.ip);
        let second = state.identify(account(2), 0).map(|found| found.ip);
        assert_eq!(first, Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!(second, Some(Ipv4Addr::new(10, 77, 0, 2)));
        let again = state.identify(account(1), 10).map(|found| found.ip);
        assert_eq!(again, first, "the same identity keeps its address");
    }

    #[test]
    fn names_derive_from_the_identity() {
        let mut state = State::default();
        let name = state.identify(account(1), 0).map(|found| found.name);
        assert_eq!(name.as_deref(), Some("peer-00000001"));
    }

    #[test]
    fn full_table_evicts_the_oldest_idle_identity() {
        let mut state = State::default();
        for index in 0..MAX_ACCOUNTS {
            let seen = u64::try_from(index).unwrap_or(0) + 100;
            assert!(
                state
                    .identify(account(u32::try_from(index).unwrap_or(0)), seen)
                    .is_some()
            );
        }
        let evicted = address(&state, &account(0));
        assert!(evicted.is_some());
        let newcomer = account(u32::MAX);
        let granted = state.identify(newcomer, 1_000_000).map(|found| found.ip);
        assert_eq!(granted, evicted, "the newcomer takes the oldest address");
        assert!(address(&state, &account(0)).is_none());
        assert!(address(&state, &account(1)).is_some());
    }

    #[test]
    fn touched_identity_outlives_older_ones() {
        let mut state = State::default();
        for index in 0..MAX_ACCOUNTS {
            let seen = u64::try_from(index).unwrap_or(0) + 100;
            assert!(
                state
                    .identify(account(u32::try_from(index).unwrap_or(0)), seen)
                    .is_some()
            );
        }
        state.touch(&account(0), 9_999_999);
        assert!(state.identify(account(u32::MAX), 10_000_000).is_some());
        assert!(
            address(&state, &account(0)).is_some(),
            "touched identity stays"
        );
        assert!(
            address(&state, &account(1)).is_none(),
            "next oldest is evicted"
        );
    }

    #[test]
    fn dirty_state_exports_once() {
        let mut state = State::default();
        assert!(state.take_dirty().is_none());
        assert!(state.identify(account(1), 0).is_some());
        let exported = state.take_dirty();
        assert_eq!(exported.map(|records| records.len()), Some(1));
        assert!(state.take_dirty().is_none(), "export clears the flag");
        assert!(state.identify(account(1), 10).is_some());
        assert!(
            state.take_dirty().is_none(),
            "a fresh sighting does not rewrite the file"
        );
    }

    #[test]
    fn load_keeps_addresses_and_renumbers_duplicates() {
        let (a, b) = (account(1), account(2));
        let shared = Ipv4Addr::new(10, 77, 0, 5);
        let mut records = HashMap::new();
        records.insert(
            a,
            Record {
                ip: shared,
                seen: 1,
                name: String::new(),
            },
        );
        let mut state = State::load(&records);
        assert_eq!(address(&state, &a), Some(shared));
        records.insert(
            b,
            Record {
                ip: shared,
                seen: 1,
                name: String::new(),
            },
        );
        state = State::load(&records);
        assert_eq!(state.take_dirty().map(|saved| saved.len()), Some(1));
    }
}
