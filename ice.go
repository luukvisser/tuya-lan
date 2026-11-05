package tuyalan

// The camera speaks a subset of ICE that a conformant agent cannot complete.
// It always claims the controlling role, answering 487 Role Conflict to anyone
// who claims it too, and its binding success responses carry no
// MESSAGE-INTEGRITY, which pion discards outright. On a LAN there is exactly
// one candidate pair, so the connectivity checks are done here instead: the
// pairing is a single exchange, not a NAT-traversal problem.
//
// Ported from Leonard Pitzu's leonardpitzu/aventproxy (MIT). Changed here:
// because the camera's success response carries no integrity, its source is the
// only thing that ties it to the camera, so every datagram from anywhere but
// the camera's candidate addresses is dropped, here and in the router. Checks
// against several candidates, matched by transaction id, follow Andrea
// Cervesato's pkg/lan in thekoma/aventproxy (MIT, 2026.11.0-rc1, 52f376e and
// da81ff5).

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v4"
	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	// The app uses a 4-character ufrag and a 24-character password; the camera
	// answers in kind.
	iceUfragLen = 4
	icePwdLen   = 24
	// Host candidates all carry this priority, so the value is fixed.
	icePriority = 2130706431

	iceCheckInterval = 200 * time.Millisecond
	iceStunMagic     = 0x2112A442

	// kcpHeaderLen is the fixed KCP segment header, whose first field is the
	// conversation id.
	kcpHeaderLen = 24

	attrPriority      = 0x0024
	attrICEControlled = 0x8029
)

// iceCreds is one side's short-term credentials.
type iceCreds struct {
	Ufrag string
	Pwd   string
}

func newICECreds() (iceCreds, error) {
	ufrag, err := randomASCII(iceUfragLen)
	if err != nil {
		return iceCreds{}, err
	}
	pwd, err := randomASCII(icePwdLen)
	if err != nil {
		return iceCreds{}, err
	}
	return iceCreds{Ufrag: ufrag, Pwd: pwd}, nil
}

// isSTUN reports whether a datagram is STUN rather than media.
func isSTUN(b []byte) bool {
	return len(b) >= 20 &&
		b[0]&0xC0 == 0 &&
		uint32(b[4])<<24|uint32(b[5])<<16|uint32(b[6])<<8|uint32(b[7]) == iceStunMagic
}

// bindingRequest builds one connectivity check.
//
// We announce the controlled role: the camera rejects a second controlling
// agent, and on a single pair there is nothing to nominate anyway.
func bindingRequest(local, remote iceCreds) (*stun.Message, error) {
	tiebreaker := make([]byte, 8)
	if _, err := rand.Read(tiebreaker); err != nil {
		return nil, err
	}
	priority := make([]byte, 4)
	binary.BigEndian.PutUint32(priority, icePriority)
	return stun.Build(
		stun.BindingRequest,
		stun.NewTransactionIDSetter(stun.NewTransactionID()),
		stun.NewUsername(remote.Ufrag+":"+local.Ufrag),
		&stun.RawAttribute{Type: attrPriority, Value: priority},
		&stun.RawAttribute{Type: attrICEControlled, Value: tiebreaker},
		stun.NewShortTermIntegrity(remote.Pwd),
		stun.Fingerprint,
	)
}

// bindingResponse answers the camera's own check.
func bindingResponse(req *stun.Message, from *net.UDPAddr, local iceCreds) (*stun.Message, error) {
	return stun.Build(
		stun.BindingSuccess,
		stun.NewTransactionIDSetter(req.TransactionID),
		&stun.XORMappedAddress{IP: from.IP, Port: from.Port},
		stun.NewShortTermIntegrity(local.Pwd),
		stun.Fingerprint,
	)
}

// iceConnect runs checks against the camera until one of them is answered,
// and returns the candidate that answered.
//
// peers is asked again before every round, so candidates that trickle in
// while the checks run are tried too; on the LAN route it always returns the
// one candidate the answer named. A response is matched to its check by
// transaction id, so the candidate returned is the one the check went to; a
// response that echoes no id of ours counts for the candidate it came from.
// A datagram from any address but a candidate's is dropped.
//
// A candidate that rejects its check is not checked again. The checks end at
// once only when every candidate known has rejected, which with a single
// candidate is the first rejection; otherwise the others keep their chance,
// and the last rejection is what the end of ctx reports.
//
// The camera's response is deliberately not authenticated: it omits the
// integrity attribute, so its arrival from the candidate is the only signal
// available.
func iceConnect(ctx context.Context, sock *net.UDPConn, peers func() []*net.UDPAddr, local, remote iceCreds) (*net.UDPAddr, error) {
	// The checks poll with a read deadline; leaving it set would make every
	// later media read fail instantly.
	defer func() { _ = sock.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 2048)
	sent := map[[stun.TransactionIDSize]byte]*net.UDPAddr{}
	rejected := map[string]bool{}
	var lastRejection error
	next := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			if lastRejection != nil {
				return nil, lastRejection
			}
			return nil, fmt.Errorf("tuyalan: no answer to the ICE checks: %w", err)
		}
		if time.Now().After(next) {
			for _, peer := range peers() {
				if rejected[peer.String()] {
					continue
				}
				req, err := bindingRequest(local, remote)
				if err != nil {
					return nil, err
				}
				if _, err := sock.WriteToUDP(req.Raw, peer); err != nil {
					return nil, err
				}
				sent[req.TransactionID] = peer
			}
			next = time.Now().Add(iceCheckInterval)
		}

		if err := sock.SetReadDeadline(time.Now().Add(iceCheckInterval)); err != nil {
			return nil, err
		}
		n, from, err := sock.ReadFromUDP(buf)
		if isTimeout(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if candidate(from, peers()) == nil {
			debugf("tuyalan: ignoring a %d-byte datagram from %s during the ICE check", n, from)
			continue
		}
		if !isSTUN(buf[:n]) {
			continue
		}
		msg := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
		if err := msg.Decode(); err != nil {
			continue
		}
		switch msg.Type.Class {
		case stun.ClassSuccessResponse:
			if peer := checked(sent, msg.TransactionID, from, peers()); peer != nil {
				return peer, nil
			}
		case stun.ClassRequest:
			if resp, err := bindingResponse(msg, from, local); err == nil {
				_, _ = sock.WriteToUDP(resp.Raw, from)
			}
		case stun.ClassErrorResponse:
			peer := checked(sent, msg.TransactionID, from, peers())
			var code stun.ErrorCodeAttribute
			if peer == nil || code.GetFrom(msg) != nil {
				continue
			}
			rejected[peer.String()] = true
			lastRejection = fmt.Errorf("tuyalan: camera rejected the ICE check: %d %s", code.Code, code.Reason)
			if allRejected(peers(), rejected) {
				return nil, lastRejection
			}
		}
	}
}

// checked names the candidate a response answers: the one its transaction id
// went to, or else the candidate it came from, for a camera that does not
// echo the id (RFC 5389 says it must). A response from an address we never
// checked answers nothing.
func checked(sent map[[stun.TransactionIDSize]byte]*net.UDPAddr, tx [stun.TransactionIDSize]byte, from *net.UDPAddr, peers []*net.UDPAddr) *net.UDPAddr {
	if peer, ok := sent[tx]; ok {
		return peer
	}
	return candidate(from, peers)
}

// candidate is the candidate a datagram came from, or nil.
func candidate(from *net.UDPAddr, peers []*net.UDPAddr) *net.UDPAddr {
	for _, p := range peers {
		if samePeer(from, p) {
			return p
		}
	}
	return nil
}

// allRejected reports whether every candidate has rejected its check.
func allRejected(peers []*net.UDPAddr, rejected map[string]bool) bool {
	for _, p := range peers {
		if !rejected[p.String()] {
			return false
		}
	}
	return true
}

// onePeer is the candidate list of a LAN session: the answer names one.
func onePeer(peer *net.UDPAddr) func() []*net.UDPAddr {
	return func() []*net.UDPAddr { return []*net.UDPAddr{peer} }
}

// isTimeout reports a read deadline passing, as opposed to a failed
// connection. kcp-go's timeout unwraps to a net.Error too.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// samePeer reports whether a datagram came from the camera's candidate.
func samePeer(from, peer *net.UDPAddr) bool {
	return from != nil && peer != nil && from.Port == peer.Port && from.IP.Equal(peer.IP)
}

// hostCandidate renders the SDP line for a socket the camera can reach.
func hostCandidate(ip net.IP, port int) string {
	return fmt.Sprintf("candidate:1 1 UDP %d %s %d typ host", icePriority, ip, port)
}

// localAddrFor reports the address this host uses to reach the camera.
func localAddrFor(peer *net.UDPAddr) (net.IP, error) {
	probe, err := net.DialUDP("udp4", nil, peer)
	if err != nil {
		return nil, err
	}
	defer probe.Close()
	return probe.LocalAddr().(*net.UDPAddr).IP, nil
}

// Debugf, when set, receives protocol-level tracing. It exists because the
// media path can only be diagnosed against real hardware.
var Debugf func(format string, args ...any)

func debugf(format string, args ...any) {
	if Debugf != nil {
		Debugf(format, args...)
	}
}

// The camera runs two KCP conversations over the one socket: conv 0 carries
// the control messages, conv 1 the media. A kcp session is bound to a single
// conv and drops everything else, so the datagrams are demultiplexed here and
// each conversation gets its own session.
type packetRouter struct {
	sock  *net.UDPConn
	peer  *net.UDPAddr
	key   []byte
	local iceCreds

	mu    sync.Mutex
	conns map[uint32]*convConn
	// opened announces a conversation the camera started.
	opened chan uint32
	done   chan struct{}

	// What arrived and what was dropped before KCP, so a session without
	// video can tell a camera that sent nothing from datagrams lost here.
	datagrams, foreign, badMAC, queueFull atomic.Uint64
}

func newPacketRouter(sock *net.UDPConn, peer *net.UDPAddr, key []byte, local iceCreds) *packetRouter {
	r := &packetRouter{
		sock:   sock,
		peer:   peer,
		key:    key,
		local:  local,
		conns:  map[uint32]*convConn{},
		opened: make(chan uint32, 8),
		done:   make(chan struct{}),
	}
	go r.run()
	return r
}

// conn returns the packet channel for one conversation.
func (r *packetRouter) conn(conv uint32) *convConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.conns[conv]
	if !ok {
		c = &convConn{router: r, in: make(chan []byte, 1024)}
		r.conns[conv] = c
	}
	return c
}

func (r *packetRouter) run() {
	buf := make([]byte, 65535)
	for {
		n, from, err := r.sock.ReadFromUDP(buf)
		if err != nil {
			close(r.done)
			return
		}
		if !samePeer(from, r.peer) {
			r.foreign.Add(1)
			continue
		}
		r.datagrams.Add(1)
		if isSTUN(buf[:n]) {
			msg := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
			if msg.Decode() == nil && msg.Type.Class == stun.ClassRequest {
				if resp, err := bindingResponse(msg, from, r.local); err == nil {
					_, _ = r.sock.WriteToUDP(resp.Raw, from)
				}
			}
			continue
		}
		if n < macLen+kcpHeaderLen {
			continue
		}
		body := buf[: n-macLen : n-macLen]
		if !hmac.Equal(mac(r.key, body), buf[n-macLen:n]) {
			r.badMAC.Add(1)
			debugf("media: MAC mismatch on %d-byte datagram", n)
			continue
		}
		if Debugf != nil && len(body) >= kcpHeaderLen {
			conv := binary.LittleEndian.Uint32(body[0:4])
			r.mu.Lock()
			_, known := r.conns[conv]
			r.mu.Unlock()
			if !known {
				debugf("tuyalan: camera opened conversation %d", conv)
			}
		}
		conv := binary.LittleEndian.Uint32(body[:4])
		r.mu.Lock()
		c, known := r.conns[conv]
		if !known {
			c = &convConn{router: r, in: make(chan []byte, 1024)}
			r.conns[conv] = c
		}
		r.mu.Unlock()
		if !known {
			// The camera chooses the media conversation id per session, so the
			// session is attached when the first segment for it arrives.
			select {
			case r.opened <- conv:
			default:
			}
		}
		select {
		case c.in <- append([]byte{}, body...):
		default:
			r.queueFull.Add(1)
			debugf("tuyalan: conversation %d queue full, dropping a segment", conv)
		}
	}
}

func (r *packetRouter) Close() error { return r.sock.Close() }

// convConn presents one conversation to kcp as if it owned the socket.
type convConn struct {
	router   *packetRouter
	in       chan []byte
	deadline atomic.Pointer[time.Time]
}

func (c *convConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timeout <-chan time.Time
	if d := c.deadline.Load(); d != nil && !d.IsZero() {
		t := time.NewTimer(time.Until(*d))
		defer t.Stop()
		timeout = t.C
	}
	select {
	case b := <-c.in:
		return copy(p, b), c.router.peer, nil
	case <-c.router.done:
		return 0, c.router.peer, net.ErrClosed
	case <-timeout:
		return 0, c.router.peer, os.ErrDeadlineExceeded
	}
}

func (c *convConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	out := append(append([]byte{}, p...), mac(c.router.key, p)...)
	if _, err := c.router.sock.WriteToUDP(out, c.router.peer); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *convConn) Close() error        { return nil }
func (c *convConn) LocalAddr() net.Addr { return c.router.sock.LocalAddr() }

func (c *convConn) SetDeadline(t time.Time) error {
	c.deadline.Store(&t)
	return nil
}
func (c *convConn) SetReadDeadline(t time.Time) error { return c.SetDeadline(t) }
func (c *convConn) SetWriteDeadline(time.Time) error  { return nil }

// convControl is the conversation the camera answers control messages on;
// the media conversation id varies per session.
const convControl = 0

// newKCP starts one conversation on the shared socket.
func newKCP(r *packetRouter, conv uint32, peer *net.UDPAddr) (*kcp.UDPSession, error) {
	s, err := kcp.NewConn3(conv, peer, nil, 0, 0, r.conn(conv))
	if err != nil {
		return nil, err
	}
	// Message mode is kcp-go's default; set anyway, since the media channel
	// depends on it. SetStreamMode is deprecated without a replacement in kcp-go v5.
	//lint:ignore SA1019 explicit message mode, see above
	s.SetStreamMode(false) //nolint:staticcheck // SA1019, see above
	s.SetWindowSize(512, 512)
	s.SetNoDelay(1, 10, 2, 1)
	return s, nil
}
