# Overlay network release gate

The overlay network lets broadcasting VPN connections reach each other by private address through the connected server's hub.
Local implementation evidence does not establish deployment or routed-transfer acceptance.
Acceptance must succeed through the established VPN without opening a separate public port or changing host firewalls.

| Required property | Procedure and objective pass condition | Current evidence | Status |
| --- | --- | --- | --- |
| Hub isolation | Hidden accounts are never listed, reachable or distinguishable from absent addresses; unadmitted sources are closed before any frame | Go loopback tests (`server/hub_runtime_test.go`) | NOT RUN on a real server |
| Magic DNS | Resolve a live peer under `on.snoo` through the native OS resolver. Disconnect it, reuse its address, and verify the name does not follow the address or leak upstream | App UDP/TCP integration tests | NOT RUN on installed clients |
| Storage rollback | Preserve address, room membership and durable name ownership through a Rust → Go → Rust restart on the same data directory | `TestHubStorageUpgradeAndRollback` | Passed locally |
| Direct WebRTC | Transfer TCP and UDP payload with relay disabled between native v4 and v5 peers in both initiation orders; compare with a v4 pair on the same network | `TestMixedWireDirect` | Passed on loopback |
| Native deployment | Deploy the overlay hub container on a real owned server, connect two broadcasting clients and one hidden client, exchange TCP and UDP bytes, and confirm the hidden client cannot be reached | No Docker runtime in this environment; no live server was contacted | NOT RUN |
| Client routing | On Linux and Windows, verify the assigned address, routed flows through the tunnel and teardown of the address alias | Build and unit tests only | NOT RUN |
| Internet interface | On AWS, GCP and Vultr hosts, `inspect` reports the real outbound interface, never a bridge or veth | Bash tests with simulated routes cover ens5, docker0 fall-through and veth rejection | NOT RUN on real providers |

The overlay network remains **NOT READY for release** until the outstanding native and live integration criteria pass.