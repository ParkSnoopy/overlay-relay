package overlayagent

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func (a *Agent) peerIDLocked(ip netip.Addr) string { return a.peerSet[ip] }

type peerObservation struct {
	id              string
	status          overlay.DirectStatus
	path            overlay.FlowPath
	attempts        int
	failed          bool
	activityAt      time.Time
	activityPath    overlay.FlowPath
	unansweredSince time.Time
	rateAt          time.Time
	rateBytes       uint64
	bytesPerSecond  float64
}

const peerActivityDuration = 1500 * time.Millisecond
const peerUnansweredAfter = 15 * time.Second

func (a *Agent) peerActivityLocked(ip netip.Addr, now time.Time) overlay.PeerActivity {
	o := a.observations[ip]
	if o.attempts > 0 || (!o.unansweredSince.IsZero() && now.Sub(o.unansweredSince) >= peerUnansweredAfter) {
		return overlay.ActivityWaiting
	}
	if o.activityAt.IsZero() || now.Sub(o.activityAt) >= peerActivityDuration {
		return overlay.ActivityIdle
	}
	if o.failed {
		return overlay.ActivityFailed
	}
	return overlay.PeerActivity(o.activityPath)
}

// Traffic publishes transitions immediately, never events per packet. The
// session-owned timer expires bursts, advances unanswered sends and samples rates.
func (a *Agent) refreshActivity() {
	a.mu.Lock()
	next := make(map[netip.Addr]overlay.PeerActivity, len(a.peers))
	changed := false
	now := time.Now()
	for _, peer := range a.peers {
		ip, _ := netip.ParseAddr(peer.IP)
		if o, ok := a.observations[ip]; ok && !o.rateAt.IsZero() {
			if elapsed := now.Sub(o.rateAt); elapsed >= time.Second {
				rate := float64(o.rateBytes) / elapsed.Seconds()
				changed = changed || rate != o.bytesPerSecond
				o.bytesPerSecond, o.rateBytes, o.rateAt = rate, 0, now
				a.observations[ip] = o
			}
		}
		activity := a.peerActivityLocked(ip, now)
		next[ip] = activity
		changed = changed || a.activityStates[ip] != activity
	}
	a.activityStates = next
	a.mu.Unlock()
	if changed {
		a.emit()
	}
}

func (a *Agent) beginAttempt(ip netip.Addr, id string) func(bool) {
	a.mu.Lock()
	if !a.connected || a.peerIDLocked(ip) != id {
		a.mu.Unlock()
		return func(bool) {}
	}
	epoch := a.sessionEpoch
	if a.observations == nil {
		a.observations = make(map[netip.Addr]peerObservation)
	}
	o := a.observations[ip]
	if o.id != id {
		o = peerObservation{id: id}
	}
	o.attempts++
	a.observations[ip] = o
	a.mu.Unlock()
	a.emit()
	return func(succeeded bool) {
		a.mu.Lock()
		if o, ok := a.observations[ip]; ok && o.id == id && a.sessionEpoch == epoch && o.attempts > 0 {
			o.attempts--
			o.failed = !succeeded
			if !succeeded {
				o.activityAt = time.Now()
			}
			a.observations[ip] = o
		}
		a.mu.Unlock()
		a.emit()
	}
}

func (a *Agent) recordDirect(ip netip.Addr, id string, status overlay.DirectStatus) {
	a.mu.Lock()
	if a.connected && a.peerIDLocked(ip) == id {
		if a.observations == nil {
			a.observations = make(map[netip.Addr]peerObservation)
		}
		observation := a.observations[ip]
		if observation.id != id {
			observation = peerObservation{id: id}
		}
		observation.status = status
		a.observations[ip] = observation
	}
	a.mu.Unlock()
	a.emit()
}

func (a *Agent) trackFlowLocked(flow *peerFlow) {
	flow.agent, flow.epoch = a, a.sessionEpoch
	if a.active == nil {
		a.active = make(map[*peerFlow]struct{})
	}
	a.active[flow] = struct{}{}
	ip, id := flow.ip, flow.peerID
	if a.connected && a.peerIDLocked(ip) == id {
		if a.observations == nil {
			a.observations = make(map[netip.Addr]peerObservation)
		}
		observation := a.observations[ip]
		if observation.id != id {
			observation = peerObservation{id: id}
		}
		observation.path = overlay.PathRelay
		observation.failed = false
		if flow.direct {
			observation.path, observation.status = overlay.PathDirect, overlay.DirectSucceeded
		}
		a.observations[ip] = observation
	}
}

// peerFlow retains the underlying half-close contract and removes its live
// path exactly once, even when cancellation and both splice directions close.
type peerFlow struct {
	net.Conn
	agent   *Agent
	ip      netip.Addr
	peerID  string
	direct  bool
	relay   *relayAdmission
	epoch   uint64
	revoked atomic.Bool
	once    sync.Once
	err     error
}

func (f *peerFlow) Read(p []byte) (int, error) {
	if f.revoked.Load() {
		return 0, net.ErrClosed
	}
	n, err := f.Conn.Read(p)
	if f.revoked.Load() {
		return 0, net.ErrClosed
	}
	f.recordTraffic(n, err, false)
	return n, err
}

func (f *peerFlow) Write(p []byte) (int, error) {
	if f.revoked.Load() {
		return 0, net.ErrClosed
	}
	n, err := f.Conn.Write(p)
	f.recordTraffic(n, err, true)
	return n, err
}

func (f *peerFlow) recordTraffic(n int, err error, sent bool) {
	failed := err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe)
	if n == 0 && !failed {
		return
	}
	a := f.agent
	a.mu.Lock()
	o, ok := a.observations[f.ip]
	if !ok || o.id != f.peerID || f.epoch != a.sessionEpoch {
		a.mu.Unlock()
		return
	}
	if _, active := a.active[f]; !active || f.revoked.Load() {
		a.mu.Unlock()
		return
	}
	now := time.Now()
	o.activityAt, o.failed = now, failed
	o.activityPath = overlay.PathRelay
	if f.direct {
		o.activityPath = overlay.PathDirect
	}
	if n > 0 {
		if o.rateAt.IsZero() {
			o.rateAt = now
		}
		o.rateBytes += uint64(n)
		if !sent {
			o.unansweredSince = time.Time{}
		} else if o.unansweredSince.IsZero() {
			o.unansweredSince = now
		}
	}
	a.observations[f.ip] = o
	activity := a.peerActivityLocked(f.ip, now)
	changed := a.activityStates[f.ip] != activity
	if changed {
		if a.activityStates == nil {
			a.activityStates = make(map[netip.Addr]overlay.PeerActivity)
		}
		a.activityStates[f.ip] = activity
	}
	a.mu.Unlock()
	if changed {
		a.emit()
	}
}

func (f *peerFlow) Close() error {
	f.once.Do(func() {
		if f.relay != nil {
			f.relay.cancel()
		}
		f.err = f.Conn.Close()
		f.agent.mu.Lock()
		delete(f.agent.active, f)
		live := false
		for flow := range f.agent.active {
			live = live || (flow.epoch == f.epoch && flow.ip == f.ip && flow.peerID == f.peerID)
		}
		if !live {
			o, ok := f.agent.observations[f.ip]
			if ok && o.id == f.peerID && f.epoch == f.agent.sessionEpoch {
				o.unansweredSince = time.Time{}
				f.agent.observations[f.ip] = o
			}
		}
		f.agent.mu.Unlock()
		f.agent.emit()
	})
	return f.err
}

func (f *peerFlow) CloseWrite() error {
	if writer, ok := f.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return f.Close()
}
