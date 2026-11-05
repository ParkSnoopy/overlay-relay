package tests

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v4/vnet"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

// The hub and file services use real TCP/UDP sockets. Only the underlay of
// the agents' actual STUN, hole-punching and QUIC transports is simulated.
func directNetwork(t *testing.T, nats [2]vnet.NATType, filter vnet.ChunkFilter) [2]*overlayagent.DirectOptions {
	t.Helper()
	logger := logging.NewDefaultLoggerFactory()
	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: logger, MinDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if filter != nil {
		wan.AddChunkFilter(filter)
	}
	stunNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"203.0.113.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := wan.AddNet(stunNet); err != nil {
		t.Fatal(err)
	}
	stunSocket, err := stunNet.ListenPacket("udp4", "203.0.113.1:3478")
	if err != nil {
		t.Fatal(err)
	}
	stun := serveSTUN(t, stunSocket)
	var options [2]*overlayagent.DirectOptions
	for i := range options {
		lan, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR: fmt.Sprintf("192.168.%d.0/24", i+1), StaticIPs: []string{fmt.Sprintf("198.51.100.%d", i+1)},
			NATType:       &nats[i],
			LoggerFactory: logger, MinDelay: 10 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		nic, err := vnet.NewNet(&vnet.NetConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if err := lan.AddNet(nic); err != nil {
			t.Fatal(err)
		}
		if err := wan.AddRouter(lan); err != nil {
			t.Fatal(err)
		}
		options[i] = &overlayagent.DirectOptions{
			STUNServers: []string{stun}, Timeout: 2 * time.Second,
			ListenPacket: func(context.Context) (net.PacketConn, error) {
				return nic.ListenPacket("udp4", "0.0.0.0:0")
			},
		}
	}
	if err := wan.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := wan.Stop(); err != nil {
			t.Error(err)
		}
	})
	return options
}

func TestDirectThroughNAT(t *testing.T) {
	for _, filtering := range []vnet.EndpointDependencyType{vnet.EndpointIndependent, vnet.EndpointAddrDependent, vnet.EndpointAddrPortDependent} {
		t.Run(fmt.Sprintf("filter-%d", filtering), func(t *testing.T) {
			nat := vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: filtering}
			options := directNetwork(t, [2]vnet.NATType{nat, nat}, nil)
			env := startSecureEnv(t, secureSide{transport: options[0]}, secureSide{transport: options[1]})
			for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
				transferDirect(t, env, false, proto)
			}
		})
	}
}

func TestDirectWithChangingPeerPort(t *testing.T) {
	options := directNetwork(t, [2]vnet.NATType{
		{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent},
		{MappingBehavior: vnet.EndpointAddrPortDependent, FilteringBehavior: vnet.EndpointAddrPortDependent},
	}, nil)
	env := startSecureEnv(t, secureSide{transport: options[0]}, secureSide{transport: options[1]})
	for _, reverse := range []bool{false, true} {
		for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
			transferDirect(t, env, reverse, proto)
		}
	}
}

func transferDirect(t *testing.T, env *secureEnv, reverse bool, proto string) {
	t.Helper()
	sender, target, states, sink, tap := env.alice, env.bobIP, env.aliceStates, env.bobSink, env.aliceTap
	if reverse {
		sender, target, states, sink, tap = env.bob, env.aliceIP, env.bobStates, env.aliceSink, env.bobTap
	}
	before := len(tap.snapshot())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	name := proto + ".bin"
	source := writeSource(t, name, 64<<10, true)
	_, err := sendFile(ctx, sender, target, proto, source)
	if err != nil {
		t.Fatal(err)
	}
	requireSameFile(t, source, filepath.Join(sink.dir, name))
	state := waitFor(t, states, func(state overlay.State) bool {
		return len(state.Peers) == 1 && (state.Peers[0].DirectStatus == overlay.DirectSucceeded || state.Peers[0].DirectStatus == overlay.DirectFailed)
	})
	if state.Peers[0].DirectStatus != overlay.DirectSucceeded {
		t.Fatalf("reachable peer uses a new NAT port, but direct failed: %+v", state.Peers[0])
	}
	if size := len(tap.snapshot()) - before; size > 32<<10 {
		t.Fatalf("direct payload went through the hub: %d bytes", size)
	}
}

func TestDirectThroughPacketLoss(t *testing.T) {
	nat := vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointAddrPortDependent}
	var packets atomic.Uint64
	options := directNetwork(t, [2]vnet.NATType{nat, nat}, func(vnet.Chunk) bool {
		return packets.Add(1)%7 != 0
	})
	env := startSecureEnv(t, secureSide{transport: options[0]}, secureSide{transport: options[1]})
	for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
		transferDirect(t, env, false, proto)
	}
}

func TestDirectWithoutPunchPackets(t *testing.T) {
	nat := vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent}
	options := directNetwork(t, [2]vnet.NATType{nat, nat}, func(chunk vnet.Chunk) bool {
		return !bytes.HasPrefix(chunk.UserData(), []byte{0, 'o', 'r', 'p', '1'})
	})
	env := startSecureEnv(t, secureSide{transport: options[0]}, secureSide{transport: options[1]})
	for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
		transferDirect(t, env, false, proto)
	}
}

func TestUntraversableNATUsesEncryptedRelay(t *testing.T) {
	nat := vnet.NATType{MappingBehavior: vnet.EndpointAddrPortDependent, FilteringBehavior: vnet.EndpointAddrPortDependent}
	options := directNetwork(t, [2]vnet.NATType{nat, nat}, nil)
	env := startSecureEnv(t, secureSide{transport: options[0]}, secureSide{transport: options[1]})
	source, err := sendFromAlice(t, env, secureFileSize)
	if err != nil {
		t.Fatal(err)
	}
	requireSameFile(t, source, filepath.Join(env.bobSink.dir, "from-alice.bin"))
	state := waitFor(t, env.aliceStates, func(state overlay.State) bool {
		return len(state.Peers) == 1 && state.Peers[0].LastPath == overlay.PathRelay
	})
	if state.Peers[0].DirectStatus != overlay.DirectFailed {
		t.Fatal("failed NAT traversal was not reported", state)
	}
	seen := env.aliceTap.snapshot()
	if len(seen) < secureFileSize || bytes.Contains(seen, plainMarker) {
		t.Fatal("fallback must relay the file without plaintext")
	}
}
