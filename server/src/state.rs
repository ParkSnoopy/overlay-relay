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

/// The display name every identity gets: a prefix of its verifier.
fn display_name(verifier: &Verifier) -> String {
    let hex = verifier.to_hex();
    format!("peer-{}", hex.get(..8).unwrap_or(&hex))
}

/// The hub's mutable state.
#[derive(Debug, Default)]
pub struct State {
    address_space: AddressSpace,
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
        let mut state = Self::default();
        state.address_space = address_space;
        for (verifier, record) in records {
            if !address_space.assignable(record.ip) || state.by_ip.contains_key(&record.ip) {
                state.dirty = true;
                continue;
            }
            state.by_ip.insert(record.ip, *verifier);
            state.accounts.insert(
                *verifier,
                Entry {
                    name: display_name(verifier),
                    ip: record.ip,
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
        if let Some(entry) = self.accounts.get_mut(&verifier) {
            if now.saturating_sub(entry.seen) >= SEEN_GRANULARITY {
                entry.seen = now;
                self.dirty = true;
            }
        } else {
            if self.accounts.len() >= MAX_ACCOUNTS {
                self.evict_idle()?;
            }
            let used: HashSet<Ipv4Addr> = self.by_ip.keys().copied().collect();
            let ip = self.address_space.lowest_free(&used).ok()?;
            self.by_ip.insert(ip, verifier);
            self.accounts.insert(
                verifier,
                Entry {
                    name: display_name(&verifier),
                    ip,
                    seen: now,
                },
            );
            self.dirty = true;
        }
        let entry = self.accounts.get(&verifier)?;
        Some(Requester {
            room: String::new(),
            verifier,
            name: entry.name.clone(),
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
    fn evict_idle(&mut self) -> Option<()> {
        let oldest = self
            .accounts
            .iter()
            .filter(|(verifier, _)| {
                !self.controls.contains_key(verifier) && self.flow_count(verifier) == 0
            })
            .min_by_key(|(_, entry)| entry.seen)
            .map(|(verifier, _)| *verifier)?;
        if let Some(entry) = self.accounts.remove(&oldest) {
            self.by_ip.remove(&entry.ip);
        }
        self.pending
            .retain(|_, pending| pending.requester != oldest && pending.destination != oldest);
        self.dirty = true;
        Some(())
    }

    /// The overlay address of a known identity.
    #[must_use]
    pub fn address_of(&self, verifier: &Verifier) -> Option<Ipv4Addr> {
        self.accounts.get(verifier).map(|entry| entry.ip)
    }

    /// Updates only the authenticated device's transient advertised name.
    pub fn set_name(&mut self, verifier: &Verifier, name: &str) -> Option<String> {
        let entry = self.accounts.get_mut(verifier)?;
        entry.name = if name.is_empty() {
            display_name(verifier)
        } else {
            name.to_owned()
        };
        Some(entry.name.clone())
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
                    name: entry.name.clone(),
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
        self.flows.remove(&flow);
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
            },
        );
        let mut state = State::load(&records);
        assert_eq!(address(&state, &a), Some(shared));
        records.insert(
            b,
            Record {
                ip: shared,
                seen: 1,
            },
        );
        state = State::load(&records);
        assert_eq!(state.take_dirty().map(|saved| saved.len()), Some(1));
    }
}
