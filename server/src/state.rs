//! Hub state: the accounts table, live control streams, pending open requests
//! and active flows. Callers hold the state lock only for these synchronous
//! operations and never across an await point.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::control::ControlHandle;
use crate::protocol::{MAX_FLOWS_PER_ACCOUNT, MAX_PENDING_PER_ACCOUNT, Peer};
use crate::verifier::Verifier;

/// An authenticated account, as seen by one stream.
#[derive(Debug, Clone)]
pub struct Requester {
    /// The account's verifier.
    pub verifier: Verifier,
    /// The account's display name, sent only in its own control reply.
    pub name: String,
    /// The account's overlay address.
    pub ip: Ipv4Addr,
}

/// An open request waiting for its destination to accept.
#[derive(Debug)]
pub struct Pending {
    /// Verifier of the account that asked.
    pub requester: Verifier,
    /// Verifier of the account that must accept.
    pub destination: Verifier,
    /// Hands the acceptor's stream to the waiting open request.
    pub accept: oneshot::Sender<TcpStream>,
}

#[derive(Debug)]
struct FlowEntry {
    accounts: [Verifier; 2],
    cancel: CancellationToken,
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    ip: Ipv4Addr,
}

/// What a peers-table replacement changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableChange {
    /// Accounts in the table after the change.
    pub accounts: usize,
    /// Control streams closed because their account was removed.
    pub closed_controls: usize,
    /// Flows cancelled because one of their accounts was removed.
    pub closed_flows: usize,
}

/// The hub's mutable state.
#[derive(Debug, Default)]
pub struct State {
    accounts: HashMap<Verifier, Entry>,
    by_ip: HashMap<Ipv4Addr, Verifier>,
    controls: HashMap<Verifier, ControlHandle>,
    pending: HashMap<String, Pending>,
    flows: HashMap<u64, FlowEntry>,
    serial: u64,
}

impl State {
    /// Returns a fresh identifier for controls and flows.
    pub const fn next_serial(&mut self) -> u64 {
        self.serial += 1;
        self.serial
    }

    /// Replaces the accounts table. Accounts that disappear lose their control
    /// stream, their flows and their pending requests.
    pub fn replace_table(&mut self, entries: Vec<(Verifier, String, Ipv4Addr)>) -> TableChange {
        let kept: HashSet<Verifier> = entries.iter().map(|(verifier, _, _)| *verifier).collect();
        let removed: HashSet<Verifier> = self
            .accounts
            .keys()
            .filter(|verifier| !kept.contains(verifier))
            .copied()
            .collect();
        let mut closed_controls = 0;
        for verifier in &removed {
            if let Some(control) = self.controls.remove(verifier) {
                control.close.cancel();
                closed_controls += 1;
            }
        }
        self.pending
            .retain(|_, pending| !removed.contains(&pending.requester) && !removed.contains(&pending.destination));
        let mut closed_flows = 0;
        for flow in self.flows.values() {
            if flow.accounts.iter().any(|verifier| removed.contains(verifier)) {
                flow.cancel.cancel();
                closed_flows += 1;
            }
        }
        self.accounts.clear();
        self.by_ip.clear();
        for (verifier, name, ip) in entries {
            self.by_ip.insert(ip, verifier);
            self.accounts.insert(verifier, Entry { name, ip });
        }
        self.notify_all();
        TableChange {
            accounts: self.accounts.len(),
            closed_controls,
            closed_flows,
        }
    }

    /// Finds the account whose verifier matches `verifier`. Every stored
    /// verifier is compared, so lookup time does not depend on the match.
    #[must_use]
    pub fn authenticate(&self, verifier: &Verifier) -> Option<Requester> {
        let mut found = None;
        for (stored, entry) in &self.accounts {
            if stored.matches(verifier) {
                found = Some(Requester {
                    verifier: *stored,
                    name: entry.name.clone(),
                    ip: entry.ip,
                });
            }
        }
        found
    }

    /// The overlay address of an account in the table.
    #[must_use]
    pub fn address_of(&self, verifier: &Verifier) -> Option<Ipv4Addr> {
        self.accounts.get(verifier).map(|entry| entry.ip)
    }

    /// Lists every other broadcasting account, sorted by overlay address.
    #[must_use]
    pub fn snapshot(&self, self_verifier: Verifier) -> Vec<Peer> {
        let mut listed: Vec<(Ipv4Addr, Peer)> = Vec::new();
        for verifier in self.controls.keys() {
            if *verifier == self_verifier {
                continue;
            }
            if let Some(entry) = self.accounts.get(verifier) {
                let peer = Peer {
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
        accept: oneshot::Sender<TcpStream>,
    ) -> Option<(Verifier, ControlHandle)> {
        let dest = *self.by_ip.get(&destination)?;
        let allowed = dest != requester.verifier
            && self.controls.contains_key(&requester.verifier)
            && self.controls.contains_key(&dest)
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
                requester: requester.verifier,
                destination: dest,
                accept,
            },
        );
        Some((dest, target))
    }

    /// Removes and returns the pending request `id` if `acceptor` is its destination.
    pub fn claim_pending(&mut self, id: &str, acceptor: &Verifier) -> Option<Pending> {
        let owned = self
            .pending
            .get(id)
            .is_some_and(|pending| pending.destination == *acceptor);
        if owned { self.pending.remove(id) } else { None }
    }

    /// Removes the pending request `id` regardless of its destination.
    pub fn remove_pending(&mut self, id: &str) -> Option<Pending> {
        self.pending.remove(id)
    }

    /// Registers an active flow between two accounts. Returns `None` when an
    /// account is missing from the table or already holds its flow limit.
    pub fn open_flow(&mut self, accounts: [Verifier; 2], cancel: CancellationToken) -> Option<u64> {
        let known = accounts.iter().all(|verifier| self.accounts.contains_key(verifier));
        let capacity = accounts
            .iter()
            .all(|verifier| self.flow_count(verifier) < MAX_FLOWS_PER_ACCOUNT);
        if !(known && capacity) {
            return None;
        }
        let id = self.next_serial();
        self.flows.insert(id, FlowEntry { accounts, cancel });
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
    use std::net::Ipv4Addr;

    use tokio_util::sync::CancellationToken;

    use super::State;
    use crate::protocol::MAX_FLOWS_PER_ACCOUNT;
    use crate::verifier::Verifier;

    fn account(byte: u8) -> Verifier {
        Verifier::from_digest([byte; 32])
    }

    #[test]
    fn flow_limit_applies_per_account() {
        let (a, b) = (account(1), account(2));
        let mut state = State::default();
        let change = state.replace_table(vec![
            (a, "a".to_owned(), "10.77.0.1".parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED)),
            (b, "b".to_owned(), "10.77.0.2".parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED)),
        ]);
        assert_eq!(change.accounts, 2);
        for index in 0..MAX_FLOWS_PER_ACCOUNT {
            assert!(
                state.open_flow([a, b], CancellationToken::new()).is_some(),
                "flow {index} must be admitted"
            );
        }
        assert!(
            state.open_flow([a, b], CancellationToken::new()).is_none(),
            "flow above the per-account limit must be refused"
        );
    }

    #[test]
    fn removed_account_cancels_its_flows_and_pending_requests() {
        let (a, b) = (account(1), account(2));
        let mut state = State::default();
        state.replace_table(vec![
            (a, "a".to_owned(), "10.77.0.1".parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED)),
            (b, "b".to_owned(), "10.77.0.2".parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED)),
        ]);
        let token = CancellationToken::new();
        assert!(state.open_flow([a, b], token.clone()).is_some());
        let change = state.replace_table(vec![(
            b,
            "b".to_owned(),
            "10.77.0.2".parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED),
        )]);
        assert_eq!(change.closed_flows, 1);
        assert!(token.is_cancelled(), "the flow of a removed account must be cancelled");
    }
}
