# Changelog

## Unreleased

- Build the current `overlay-hub` with Go. The local Dockerfile remains available.
- Keep the hub and client in the root Go module without changing public import paths.
- Read the release and wire generation from the shared root `version.go`.
- Serve `device-name.on.snoo` from the client. Replace old `device-name.snoo` names.
- Advertise the hub-assigned domain to the owner and its peers. Number colliding names without changing device IDs or existing DNS ownership.
- Preserve hub-owned name bindings across reconnects, restarts, and address reuse.
- Withdraw name answers when the device is no longer online in the same room.