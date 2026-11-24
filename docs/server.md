# Overlay hub

Base: [`server/`](../server/README.md) (Go binary `overlay-hub`).
Client counterpart: [client](client.md).
The snoo-box server manager owns the container lifecycle and selected CIDR. The hub owns peer addresses, reservations, and names.
The [wire contract](../client/overlay/overlay.go) owns frames, datagram records, the address space and identity messages.

The hub is an authenticated rendezvous and byte relay between the VPN clients of one managed server that chose to broadcast.
`overlay-hub` runs it inside its container. The readiness probe is `server-helper overlay-probe <host:port>` in snoo-box, built on `client/overlayagent.Probe`.
The hub enrolls nobody: each client generates its own P-384 key pair, and a client that signs a fresh hub challenge with the key it presented is that key's peer. The same key is always the same peer. Each hub connection must use an authenticated VPN because the handshake does not authenticate the hub or prevent active interception.

## Inputs

- `OVERLAY_ALLOWED_HOST` is an optional comma-separated list of engine container names. Without it the hub admits every loopback, private or link-local source.
- `OVERLAY_CIDR` selects a canonical IPv4 `/8` through `/30` subnet wholly within RFC 1918 private space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), default `10.77.0.0/16`. Clients must configure the same range. Public ranges and supernets crossing private block boundaries are rejected. The administrator owns routing conflicts.
- `/var/lib/overlay-relay` holds `ips.json`, `rooms.json`, `dhcp.json`, `peers.json`, `peer-cache.json`, and `names.json`.

## Admission

The hub resolves every allowed host through Docker DNS on each connection and compares the connection's source address with the result.
A source that is not an allowed engine container is closed before any frame is read.
With an allowed-host list and no resolvable host the hub fails closed.
The container never publishes `6697/tcp` to the host: it is reachable only through `snoo-box-network`.
Source admission with the allowed-host list still closes any source that is not an allowed engine container.

## Identities and addresses

A peer is a public key. Authentication assigns a reserved address or the lowest free address across the entire usable selected CIDR. The network and broadcast addresses are excluded. All permanent reservations are skipped for dynamic assignment, including reservations for offline peers. Changing the configured range can reassign dynamic addresses.
Peers are written atomically with mode `0600` to `ips.json` keyed by verifier, together with the time they were last seen.
The default display name of a peer is `peer-` and the first 8 hex digits of its verifier.
A control Hello may supply `name`, applied only after proof of possession of that peer's key.
The hub validates a maximum of 128 Unicode characters with no control characters or surrounding whitespace, updates only that authenticated peer and publishes fresh peer snapshots.
`ips.json` retains the last client-advertised display name, even while an operator override supplies the effective name. An empty or absent advertised name restores the default when there is no override.
The table holds at most 4096 peers, bounded also by the subnet's usable addresses.
When either limit is exhausted, a new key can reclaim the oldest idle, unreserved assignment; a configured idle lease also protects unexpired assignments. A live control stream or flow protects its address. If no entry is reclaimable the new key receives `unauthorized`.

## Peer settings and rollback

- The managed editor uses `peers managed`. A private runtime socket combines the hub's device cache with live controls. Only an authenticated live control sets `connected` to true. `peers check-managed` verifies the target before the manager stops the hub. After restart, confirm the edited identity from persisted settings independently of its reconnect timing. `peers connected` and `peers check-connected` remain available for live-only callers.
- Live peer listings include `domain` when the control has an assigned DNS name. This is independent of `domain_override`. Omit the live domain for cached or unassigned devices.
- `peers list` reports `{"devices":{"<device-id>":{"name":"","name_override":"","ip":"","binding":"","domain_override":"","connected":false}}}`. The disk-only listing does not infer connection state. `name` is the operator override or the last client name, and is empty when neither is known. `ip` is empty without an effective assignment or reservation. `binding` is empty for dynamic addressing.
- The list includes current and offline assignments, devices with a reservation or saved peer edit, and identities recorded only in the DNS ledger after address reclamation. Room-scoped DNS labels prove ownership but do not supply a display name. A device absent from all those stores is not known to the hub.
- `peers set` takes `device_id`, `name`, and `binding` as required strings and `domain` as an optional string in one JSON object, up to 4 KiB. Omit `domain` to preserve the current override or send `""` to clear it. Nonempty domains must be canonical single labels in `on.snoo`. Unknown or expired devices and bindings in use by another device are rejected.
- Stop the hub and serialize writes. Name and binding are stored in `peers.json`; detached device records and domain overrides are stored in `peer-cache.json`. Restart to apply changes. Invalid or unreadable peer settings prevent startup. The CLI refuses to list or edit a partial registry if the DNS ledger is corrupt.
- The legacy `dhcp` commands still read and write the historical `dhcp.json` format. Unshadowed `device_id` and `public_key` reservations remain effective. The hub does not allocate from the legacy `start` and `end` pool. A managed device's `binding`, even when empty, wins over its legacy reservation. Clear incompatible effective reservations before changing the CIDR.
- A device expires after seven days without authenticated activity unless `dhcp.json` sets a nonzero `lease_seconds`. Live controls and flows protect the device. Expiry removes its records, address, reservations, overrides, and DNS claims. A legacy device known only by a setting or DNS binding starts its retention window when first loaded if no last-seen time exists.
- For operation rollback, snapshot the full data directory while stopped. Restore the snapshot, including the prior presence or absence of files, before restarting the previous configuration.
- Older hubs that do not support peer or domain overrides ignore the corresponding sidecar. Keep the sidecars when rolling back so unexpired settings are available on re-upgrade. Legacy assignment, DHCP, and DNS file formats do not change. Expired records are not restored by downgrading.

## Room-local DNS

- The hub handles name registration and lookup on the authenticated control
  stream. It has no DNS listener. The [client DNS adapter](client.md#magic-dns)
  serves `device-name.on.snoo` using the hub's answer.
- The hub normalizes advertised names to lowercase labels: `Desk PC` becomes
  `desk-pc`, and `Bücher` becomes `xn--bcher-kva`. Whitespace and punctuation
  act as separators. Unicode labels use IDNA.
- The first authenticated registration for a label in a room binds that label
  to the device's full verifier. Renaming and address reclamation do not
  release previous labels; expiry removes all the device's bindings.
- A client may set a canonical `domain` (e.g. `desk-pc.on.snoo`) and mark it
  `domain_explicit` in Hello. An explicit client choice takes precedence over
  the hub's domain override. With neither one set, use the effective display
  name. A legacy proposal that differs from the derived label counts as an
  explicit choice. The hub returns the assigned domain in the reply and the
  room roster. A second device requesting `desk-pc` gets `desk-pc-2` if free;
  already claimed suffixes are skipped. Reconnecting with the same device ID
  and request reuses its claim. The name does not replace the ID in policy.
- Every verifier also has a separate `id-<base32>` label. Encode the 32 bytes
  of the hex verifier as lowercase RFC 4648 base32 without padding. This form
  is reserved for compatibility and is never advertised as a device domain.
- The hub answers only with the current IPv4 of an owner with a live control
  stream in the requester's admitted room. Disconnect or a room change removes
  the live answer, not the binding. Private room proofs are rechecked so a room
  removal or password change also stops answers under the old admission.
  Room relay policy does not control name lookup.
- `names.json` stores room keys, labels, and verifiers without room proofs or
  IPs. The hub atomically saves and syncs new bindings before serving them.
  Preserve this file across upgrades, downgrades and backups. The hub retains
  up to 16,384 explicit names until their devices expire. Corrupt or unwritable
  storage disables DNS without breaking overlay flows. Repair it and restart
  the hub before resuming DNS.
- Preserve existing `names.json` bindings when moving from Rust to Go. Do not
  seed names from `ips.json`: it lacks the room and ownership history. If no
  durable store exists, ownership starts with authenticated registration.

## Protocol

Wire v4 and v5 retain existing identity keys and room proofs. An optional `room_id` and `room` password proof confine discovery, opens and accepts to matching members. Both empty select public membership; a private room needs both. Clients derive the proof from the room ID and password, so the hub never learns the password. The hub exposes no room directory to peers and never logs proofs. A room ID is unique, and the hub keys a room by the SHA-256 hex of its ID. A private room exists only when the operator creates it, and the hub never creates one from a request. An unknown ID is refused with `room does not exist`. `overlay-hub rooms create <id> <name> <proof> [true|false]` writes the room and its relay policy to `rooms.json`; `rooms list` prints rooms and public relay policy, `rooms relay <public|key> <true|false>` changes only relay permission, and `rooms remove <key>` deletes a private room. Omitted relay flags preserve legacy permission. Disabling relay rejects new payload flows and revokes existing relay streams after a policy-file change; discovery and bounded `signal` exchanges remain available. A known ID with another password proof is refused with `room password is incorrect`. The hub reads `rooms.json` on every private-room connection, so no restart is needed. A joined device receives the room's display name as `room_name` in the hub's reply. The authenticated VPN remains mandatory.

Unreadable/corrupt room storage or an invalid selected record returns `rooms are unavailable`, never an unknown-room refusal.
Healthy rooms remain usable alongside malformed records, which listing retains as repairable placeholders.
Legacy approval arrays remain denied placeholders until explicitly replaced or removed; adding another room preserves them.
Administrative errors contain no ANSI formatting so managers can classify duplicate-room failures reliably.

The client sends a `Hello` within 10 seconds, and every frame it reads is bounded by `overlay.MaxFrame` (16 KiB on the wire).
The hub validates the public key, issues a fresh challenge, verifies its signature and looks up the public-key digest. It answers an unknown identity with `unauthorized` before closing.

- `control` registers the peer as broadcasting and replies with its address and name.
  A new control stream for the same peer replaces and closes the old one.
  The hub pushes a full `Peers` snapshot of the other broadcasting accounts to every control stream whenever the broadcasting set changes, and answers `Ping` with `Pong`.
  A control stream without a request for 90 seconds is closed.
  A reply with `name_lookup: 1` enables `{"resolve":{"id":1,"label":"desk-pc"}}`
  requests on that stream. The hub returns `{"resolved":{"id":1,"ip":"10.77.0.5"}}`.
  It omits `ip` for a negative answer and sets `unavailable: true` for an authority
  failure. The request ID must be a nonzero 32-bit unsigned integer. The room
  always comes from authentication, never from the query. Legacy clients retain
  the original ping and roster exchange. Wire v4 and v5 remain supported.
- `open` requires that the requester has a control stream and that the destination address belongs to another broadcasting account.
  The hub then pushes an `Incoming` event with a random 128-bit identifier to the destination and waits up to 10 seconds for its `accept` stream.
  Both streams then receive `ok` and are spliced: TCP with half-close, and UDP as raw datagram records, which preserves framing.
  An unknown address, a hidden account, the requester itself, a missing accept and a requester that is not broadcasting all receive the identical `unavailable` reply.
- `accept` must authenticate the destination's identity and carry a pending identifier, and each identifier is accepted once.
  Anything else receives `unauthorized`.

`open` and `accept` may carry an offer: `fingerprint` (64 hex digits, the SHA-256 of the agent's flow certificate) and `endpoint` (a public `ip:port`).
A malformed offer, an endpoint without a fingerprint, port zero and an unspecified or multicast address are refused with `invalid request`, and a refused `accept` leaves the pending request claimable.
The `Incoming` event repeats the requester's offer. Each success reply then follows the two offers:

- Both sent a fingerprint: `secure` is true and the reply carries the other side's `fingerprint`. The flow is still spliced.
- Both also sent an endpoint: `direct` is true, and the reply carries the flow `id` and the other side's `endpoint`. The hub sends the replies, relays nothing and closes both streams.
- Otherwise the reply is a plain `ok`, as before.

The hub only forwards the offers. Agents authenticate each other by the fingerprint, so anyone who watches or alters the network, and a hub that only relays, sees nothing but ciphertext. The fingerprints themselves travel through the hub, so a hub that replaces them can still intercept a flow. Run a hub you trust.

Hidden peers never appear in a `Peers` event, an error or a log line, and an account without a control stream can neither open nor accept.

## Limits

An account has at most 256 concurrent relayed flows, and a destination has at most four pending incoming requests.
An idle UDP flow closes after two minutes, and TCP has no idle limit.
A control stream whose outgoing queue is full is dropped rather than blocking the hub.
Logs exclude private keys, identifiers, payloads and peer names.

## Verification

From `server/`, use `GOWORK=off go test ./...` for the Go hub package.
See [integration checks and legacy compatibility](LLM_WIKI.md#15-testing-and-verification) for test commands and fixture requirements.
