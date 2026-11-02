# Overlay network release gate

The overlay network lets broadcasting VPN connections reach each other by private address through the connected server's hub.
Local implementation evidence does not establish deployment or routed-transfer acceptance.
Acceptance must succeed through the established VPN without opening a separate public port or changing host firewalls.

| Required property | Procedure and objective pass condition | Current evidence | Status |
| --- | --- | --- | --- |
| Hub isolation | Hidden accounts are never listed, reachable or distinguishable from absent addresses; unadmitted sources are closed before any frame | Rust hub tests (`server/tests/hub.rs`) with real loopback streams cover both | NOT RUN on a real server |
| Native deployment | Deploy the overlay hub container on a real owned server, connect two broadcasting clients and one hidden client, exchange TCP and UDP bytes, and confirm the hidden client cannot be reached | No Docker runtime in this environment; no live server was contacted | NOT RUN |
| Client routing | On Linux and Windows, verify the assigned address, routed flows through the tunnel and teardown of the address alias | Build and unit tests only | NOT RUN |
| Internet interface | On AWS, GCP and Vultr hosts, `inspect` reports the real outbound interface, never a bridge or veth | Bash tests with simulated routes cover ens5, docker0 fall-through and veth rejection | NOT RUN on real providers |

The overlay network remains **NOT READY for release** until the outstanding native and live integration criteria pass.