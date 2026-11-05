package tuyalan

// Ported from Leonard Pitzu's leonardpitzu/aventproxy (MIT). Changed here: the
// address comes from a list of candidates instead of a discovery broadcast, the
// protocol version is chosen per camera (3.5 or 3.4), Start runs under the
// caller's context with a deadline on every step, the UDP socket binds the
// address the camera is reached from, and a dropped session is reported through
// OnError. From Andrea Cervesato's pkg/lan in thekoma/aventproxy (MIT,
// 2026.11.0-rc1): the cloud route (Signaller, cloud.go), the optional media
// idle check (MediaIdleTimeout, with a monotonic clock), OnControl, and a start
// error that keeps the step the start stopped at.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// answerTimeout bounds the wait for the camera's answer and candidate. An
// SCD951 sends both straight after the offer. A variable so the tests can
// shorten it.
var answerTimeout = 8 * time.Second

const (
	// candidateGrace is how long to wait for a candidate on the address the
	// TCP session uses once some other candidate is in hand.
	candidateGrace = time.Second
	// iceTimeout bounds the connectivity checks. The camera gives up on the
	// session 15 s after the offer (close_reason 10, measured on an SCD951), so
	// waiting longer is pointless.
	iceTimeout = 8 * time.Second
)

// DefaultStartupGap is the longest pause between two messages of the startup
// sequence when Client.StartupGap is zero. It comes from the original
// pkg/lan, which slept this long after every message without saying why.
// The camera answers each setup message on the control conversation (never
// the login), so the next one goes out as soon as that answer is in. A fixed
// 20 ms pause brought sessions up in 0.2-0.4 s but stays unproven: once in
// five starts an SCD951 then sent no video, which also happened once with
// 400 ms waits (2026-11-04).
const DefaultStartupGap = 120 * time.Millisecond

// Client streams from one camera over the local network, without the cloud.
//
// The only credentials it needs are the device's localKey and the P2P password
// from the cloud RTC config. Both are stable across sessions, so a caller can
// fetch them from Tuya's cloud once and keep them.
type Client struct {
	DeviceID string
	LocalKey string
	Password string
	UID      string
	// Hosts are the addresses to try, with or without a port. Each one is
	// tried until a handshake completes; the handshake proves the localKey, so
	// a list shared by several cameras is fine.
	Hosts []string
	// Versions is the order protocol versions are tried in, see VersionOrder.
	Versions []Version
	// ProbeTimeout bounds the handshake for every version but the last one
	// tried, HandshakeTimeout the last one. Zero means ProbeHandshakeTimeout
	// and DefaultHandshakeTimeout.
	ProbeTimeout     time.Duration
	HandshakeTimeout time.Duration

	// StreamType, when not nil, is sent as "stream_type" in the offer; nil
	// leaves it out. On the SCD951, 0, 1 and 2 made no difference.
	StreamType *int

	// Clarity is the video clarity asked for in the startup sequence:
	// ClarityHD or ClarityStandard. Zero means ClarityStandard, what the app
	// asks for: less work for the camera next to the parent unit.
	Clarity uint32

	// StartupGap is the longest pause between two messages of the startup
	// sequence (the login and six setup messages): the next one goes out when
	// the camera has answered the previous one, or after this long. There is
	// none after the last one. Zero means DefaultStartupGap, a negative value
	// sends them back to back without waiting for answers.
	StartupGap time.Duration

	// OnError is called once if the session ends after Start returned: the
	// camera closed the control connection, refused the session, or stopped
	// answering heartbeats. It is not called after Close.
	OnError func(error)

	// OnDPS, when set before Start, receives the data points the camera
	// pushes on the control connection, with the time they arrived.
	OnDPS func(dps map[string]any, at time.Time)

	// Signaller, when set, carries the session's 302 frames instead of the
	// 6668 session: the cloud route, for cameras that take no LAN offer. The
	// first of Hosts is then only a hint (see startCloud); MotoID and
	// ICEServers fill the offer, as the app's cloud offers carry them.
	Signaller  Signaller
	MotoID     string
	ICEServers []ICEServer

	// MediaIdleTimeout, when set, ends a running stream with ErrMediaIdle
	// through OnError once no media conversation has delivered a message for
	// that long; the check is client-wide, so a quiet conversation next to a
	// live one is fine. Zero keeps reading a quiet stream for good and leaves
	// a stall to the caller.
	MediaIdleTimeout time.Duration

	// OnControl, when set, is told the size of everything the control
	// conversation delivers after the startup sequence. Nothing reads those
	// messages; whether any came tells a refused login from a silent path.
	OnControl func(n int)

	// Host and Version say what Start connected with.
	Host    string
	Version Version

	session *Session
	// sessionID is the id our offer gave the session, set before any signal
	// can end it.
	sessionID string
	// cloud ends a cloud-signalled session at the camera (cloud.go).
	cloud  *cloudCloser
	sock   *net.UDPConn
	router *packetRouter
	// stream carries control messages, media the video and audio.
	stream *kcp.UDPSession
	media  []*kcp.UDPSession

	mu       sync.Mutex
	closed   bool
	life     context.Context
	stopLife context.CancelFunc
	failed   sync.Once
	// epoch keeps the media idle clock monotonic: a wall-clock step must
	// neither end a live stream nor hide a dead one. lastMedia is when a
	// conversation last delivered a media message, as time since epoch.
	epoch     time.Time
	lastMedia atomic.Int64
	onFrame   func(*VideoFrame)
	onAudio   func(*AudioFrame)

	statsMu sync.Mutex
	stats   Stats

	// cmdMu lets one data-point command at a time wait for its answer, which
	// watchControl hands over through waitDone.
	cmdMu    sync.Mutex
	waitMu   sync.Mutex
	waitCmd  uint32
	waitDone chan map[string]any
}

// Stats counts what the media channel delivered, so a stream that is missing
// most of its pictures can be told apart from one that never received them.
type Stats struct {
	Reads      int
	OpenErrors int
	Malformed  int
	Video      int
	Audio      int
	// StartupAnswered counts the startup messages the camera answered before
	// the next one went out, StartupLongestWait the longest of those waits
	// (a message left unanswered counts as the whole StartupGap).
	StartupAnswered    int
	StartupLongestWait time.Duration
	// StartupWaits is each wait in order, an unanswered one negative.
	StartupWaits []time.Duration
	// What the packet router saw on the media socket, before KCP: datagrams
	// from the camera, ones from another source, ones failing their MAC,
	// segments dropped on a full queue, and the conversations the camera
	// opened (control included).
	RouterDatagrams, RouterForeign, RouterBadMAC, RouterQueueFull uint64
	Conversations                                                 int
	// Other counts commands the dispatcher has no case for. Anything here is
	// media this package does not decode.
	Other map[uint32]int
}

func (c *Client) count(field *int) {
	c.statsMu.Lock()
	*field++
	c.statsMu.Unlock()
}

func (c *Client) countOther(cmd uint32) {
	c.statsMu.Lock()
	if c.stats.Other == nil {
		c.stats.Other = map[uint32]int{}
	}
	c.stats.Other[cmd]++
	c.statsMu.Unlock()
}

// Snapshot returns the counts so far.
func (c *Client) Snapshot() Stats {
	// The router first: c.mu is never held while statsMu is taken.
	c.mu.Lock()
	r := c.router
	c.mu.Unlock()
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	out := c.stats
	out.StartupWaits = append([]time.Duration(nil), c.stats.StartupWaits...)
	if r != nil {
		out.RouterDatagrams, out.RouterForeign = r.datagrams.Load(), r.foreign.Load()
		out.RouterBadMAC, out.RouterQueueFull = r.badMAC.Load(), r.queueFull.Load()
		r.mu.Lock()
		out.Conversations = len(r.conns)
		r.mu.Unlock()
	}
	out.Other = make(map[uint32]int, len(c.stats.Other))
	for cmd, n := range c.stats.Other {
		out.Other[cmd] = n
	}
	return out
}

// NewClient prepares a client; nothing touches the network until Start.
// Either callback may be nil, in which case that stream is discarded.
func NewClient(deviceID, localKey, password, uid string, hosts []string, versions []Version, onFrame func(*VideoFrame), onAudio func(*AudioFrame)) *Client {
	return &Client{
		DeviceID: deviceID,
		LocalKey: localKey,
		Password: password,
		UID:      uid,
		Hosts:    hosts,
		Versions: versions,
		onFrame:  onFrame,
		onAudio:  onAudio,
	}
}

var candidateRE = regexp.MustCompile(`candidate:(\S+) (\d+) (\S+) (\d+) (\S+) (\d+) typ (\S+)`)

// ErrMediaIdle ends a stream on which no conversation delivered a media
// message for MediaIdleTimeout.
var ErrMediaIdle = errors.New("tuyalan: no media")

// Start negotiates a session and begins streaming. It returns once the
// camera accepted the login; media follows asynchronously. Every step runs
// under ctx, so a deadline on ctx bounds the whole call. On error everything
// Start opened is closed again; when ctx ended the start, the error wraps
// both its end and the step it stopped at.
func (c *Client) Start(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			c.Close()
			if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
				err = fmt.Errorf("tuyalan: start ended: %w (%w)", cerr, err)
			}
		}
	}()
	// Reads below run under deadlines of their own; this makes a cancelled
	// ctx end them at once as well.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if c.Signaller != nil {
		return c.startCloud(ctx)
	}
	return c.startLAN(ctx)
}

// startLAN runs the offer and answer over the 6668 session.
func (c *Client) startLAN(ctx context.Context) error {
	if len(c.Hosts) == 0 {
		return errors.New("tuyalan: no address for the camera")
	}
	session, err := c.connect(ctx)
	if err != nil {
		return err
	}
	if err := c.adopt(func() { c.session = session }, session.Close); err != nil {
		return err
	}
	cameraIP := c.session.RemoteAddr().(*net.TCPAddr).IP

	// The socket binds the address this host reaches the camera from, on a
	// random port, and that pair is the only candidate offered. The camera
	// sends its media there, so a firewall has to let UDP from the camera in.
	hostIP, err := localAddrFor(&net.UDPAddr{IP: cameraIP, Port: Port})
	if err != nil {
		return err
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: hostIP})
	if err != nil {
		return err
	}
	if err := c.adopt(func() { c.sock = sock }, sock.Close); err != nil {
		return err
	}

	local, err := newICECreds()
	if err != nil {
		return err
	}
	offer, err := NewOffer(c.UID, c.DeviceID, local.Ufrag, local.Pwd)
	if err != nil {
		return err
	}
	offer.StreamType = c.StreamType
	c.sessionID = offer.SessionID
	if err := offer.SendOffer(c.session); err != nil {
		return err
	}
	port := sock.LocalAddr().(*net.UDPAddr).Port
	if err := offer.SendCandidate(c.session, hostCandidate(hostIP, port)); err != nil {
		return err
	}

	remote, aesKey, peer, err := c.awaitAnswer(ctx, cameraIP, func() error {
		if err := offer.SendOffer(c.session); err != nil {
			return err
		}
		return offer.SendCandidate(c.session, hostCandidate(hostIP, port))
	})
	if err != nil {
		return err
	}
	debugf("tuyalan: %s answered, ICE peer %s", c.DeviceID, peer)

	iceCtx, cancel := context.WithTimeout(ctx, iceTimeout)
	defer cancel()
	if _, err := iceConnect(iceCtx, sock, onePeer(peer), local, remote); err != nil {
		return err
	}
	return c.startStream(ctx, sock, peer, local, aesKey, true)
}

// lifeContext is the context the client's goroutines run under: it lives as
// long as the client, not as long as Start's ctx, which only bounds the start.
func (c *Client) lifeContext() (context.Context, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("tuyalan: client closed during start")
	}
	if c.life == nil {
		c.life, c.stopLife = context.WithCancel(context.Background())
	}
	return c.life, nil
}

// startStream logs in over the pair ICE settled on and starts the readers.
// The media path is the same whichever route carried the signalling; over the
// LAN the 6668 session also needs its keep-alive and watcher.
func (c *Client) startStream(ctx context.Context, sock *net.UDPConn, peer *net.UDPAddr, local iceCreds, aesKey []byte, overLAN bool) error {
	// The camera splits control and media across two KCP conversations, so a
	// router under both sessions sorts the datagrams by conversation id.
	router := newPacketRouter(sock, peer, aesKey, local)
	c.mu.Lock()
	c.router = router
	c.mu.Unlock()

	control, err := newKCP(router, convControl, peer)
	if err != nil {
		return err
	}
	if err := c.adopt(func() { c.stream = control }, control.Close); err != nil {
		return err
	}
	if err := c.login(ctx, aesKey); err != nil {
		return err
	}

	life, err := c.lifeContext()
	if err != nil {
		return err
	}
	c.epoch = time.Now()
	c.markMedia() // the idle clock starts with the stream
	go c.attachMedia(life, peer, aesKey)
	go drainControl(life, control, c.OnControl)
	if overLAN {
		go c.keepAlive(life)
		go c.watchControl(life)
	}
	return nil
}

func (c *Client) markMedia() { c.lastMedia.Store(int64(time.Since(c.epoch))) }

// mediaDeadline is when the stream counts as idle if nothing more arrives.
func (c *Client) mediaDeadline() time.Time {
	return c.epoch.Add(time.Duration(c.lastMedia.Load()) + c.MediaIdleTimeout)
}

// adopt hands a resource Start opened to the client, so Close releases it,
// unless Close already ran, for instance because ctx was cancelled.
func (c *Client) adopt(keep func(), release func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = release()
		return errors.New("tuyalan: client closed during start")
	}
	keep()
	return nil
}

// connect tries every host at every version until a handshake completes.
func (c *Client) connect(ctx context.Context) (*Session, error) {
	versions := c.Versions
	if len(versions) == 0 {
		versions = DefaultVersions
	}
	var errs []error
	for _, host := range c.Hosts {
		for i, v := range versions {
			if err := ctx.Err(); err != nil {
				return nil, errors.Join(append(errs, err)...)
			}
			cfg := DialConfig{Addr: host, LocalKey: c.LocalKey, Version: v, DeviceID: c.DeviceID, HandshakeTimeout: c.HandshakeTimeout}
			if i < len(versions)-1 {
				// Only a guess: keep the wrong version cheap.
				cfg.HandshakeTimeout = c.ProbeTimeout
				if cfg.HandshakeTimeout <= 0 {
					cfg.HandshakeTimeout = ProbeHandshakeTimeout
				}
			}
			started := time.Now()
			s, err := Dial(ctx, cfg)
			if err == nil {
				debugf("tuyalan: %s handshake at %s with protocol %s took %s", c.DeviceID, host, v, time.Since(started).Round(time.Millisecond))
				c.Host, c.Version = host, v
				return s, nil
			}
			debugf("tuyalan: %s handshake at %s with protocol %s failed after %s: %v", c.DeviceID, host, v, time.Since(started).Round(time.Millisecond), err)
			errs = append(errs, fmt.Errorf("%s at %s: %w", v, host, err))
			if errors.Is(err, ErrWrongKey) {
				// This version is spoken there, by a camera with another key.
				break
			}
			var opErr *net.OpError
			if errors.As(err, &opErr) && opErr.Op == "dial" {
				// Nothing listens there; another version will not change that.
				break
			}
		}
	}
	return nil, errors.Join(errs...)
}

// attachMedia starts a reader for each conversation the camera opens.
//
// Which id carries the video is not fixed: it has been seen as 1 and as 2 on
// the same camera, so the session follows whatever arrives.
func (c *Client) attachMedia(ctx context.Context, peer *net.UDPAddr, aesKey []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case conv := <-c.router.opened:
			if conv == convControl {
				continue
			}
			stream, err := newKCP(c.router, conv, peer)
			if err != nil {
				debugf("tuyalan: conversation %d could not be opened: %v", conv, err)
				continue
			}
			c.mu.Lock()
			closed := c.closed
			if !closed {
				c.media = append(c.media, stream)
			}
			c.mu.Unlock()
			if closed {
				stream.Close()
				return
			}
			go c.readLoop(ctx, stream, aesKey)
		}
	}
}

// collectAnswer waits for the camera's answer and a host candidate. A
// candidate on the address the TCP session reached is taken at once; any
// other is kept and used if no such one follows within candidateGrace. An
// SCD951 sends two.
// awaitAnswer is collectAnswer, with one more try on 3.3. Unmeasured there:
// the offer goes without the version header, as 3.4 wanted it; a camera that
// stays silent gets it once more (resend) with the header. The log says which
// one it answered.
func (c *Client) awaitAnswer(ctx context.Context, cameraIP net.IP, resend func() error) (remote iceCreds, aesKey []byte, peer *net.UDPAddr, err error) {
	remote, aesKey, peer, err = c.collectAnswer(ctx, cameraIP)
	if err != nil && c.session.Version == V33 && errors.Is(err, ErrNoSignal) {
		debugf("tuyalan: %s did not answer the 3.3 offer without the version header; trying once with it", c.DeviceID)
		c.session.SetLan302Header(true)
		if err := resend(); err != nil {
			return iceCreds{}, nil, nil, err
		}
		remote, aesKey, peer, err = c.collectAnswer(ctx, cameraIP)
	}
	if err == nil && c.session.Version == V33 {
		debugf("tuyalan: %s answered the 3.3 offer (version header in front of command 32: %t)", c.DeviceID, c.session.lan302Header)
	}
	return remote, aesKey, peer, err
}

func (c *Client) collectAnswer(ctx context.Context, cameraIP net.IP) (remote iceCreds, aesKey []byte, peer *net.UDPAddr, err error) {
	deadline := time.Now().Add(answerTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var fallback *net.UDPAddr
	var graceEnd time.Time
	for {
		wait := time.Until(deadline)
		if !graceEnd.IsZero() && time.Until(graceEnd) < wait {
			wait = time.Until(graceEnd)
		}
		if wait <= 0 {
			break
		}
		frame, err := ReadSignal(c.session, wait)
		if err != nil {
			if errors.Is(err, ErrNoSignal) && fallback != nil && remote.Ufrag != "" {
				break
			}
			return iceCreds{}, nil, nil, err
		}
		switch frame.Header.Type {
		case TypeAnswer:
			remote.Ufrag = sdpAttr(frame.Msg.SDP, "ice-ufrag")
			remote.Pwd = sdpAttr(frame.Msg.SDP, "ice-pwd")
			raw, decErr := hex.DecodeString(sdpAttr(frame.Msg.SDP, "aes-key"))
			if decErr != nil {
				return iceCreds{}, nil, nil, fmt.Errorf("tuyalan: bad aes-key in answer: %w", decErr)
			}
			aesKey = raw
		case TypeCandidate:
			if addr, parseErr := parseCandidate(frame.Msg.Candidate); parseErr == nil {
				if addr.IP.Equal(cameraIP) {
					peer = addr
				} else if fallback == nil {
					fallback = addr
					graceEnd = time.Now().Add(candidateGrace)
				}
			}
		case TypeDisconnect:
			// The camera also ends an earlier session about 11 s after it
			// closed, on this connection too: that is not a refusal of ours.
			if _, foreign := endsSession(frame, c.sessionID); foreign {
				debugf("tuyalan: %s ignored a disconnect for session %s during the answer (ours %s)", c.DeviceID, frame.Header.SessionID, c.sessionID)
				continue
			}
			return iceCreds{}, nil, nil, errors.New("tuyalan: camera refused the session")
		}
		if remote.Ufrag != "" && peer != nil {
			break
		}
	}
	if peer == nil {
		peer = fallback
	}
	if remote.Ufrag == "" || peer == nil {
		return iceCreds{}, nil, nil, errors.New("tuyalan: camera never completed the answer")
	}
	if len(aesKey) != 16 {
		return iceCreds{}, nil, nil, fmt.Errorf("tuyalan: answer carries a %d-byte aes-key", len(aesKey))
	}
	return remote, aesKey, peer, nil
}

func (c *Client) login(ctx context.Context, aesKey []byte) error {
	msgs, err := startupSequence(LoginToken(c.Password, c.LocalKey), c.Clarity)
	if err != nil {
		return err
	}
	buf := make([]byte, maxKCPMessage)
	return sendPaced(ctx, msgs, c.startupGap(), func(msg []byte) error {
		sealed, err := seal(aesKey, msg)
		if err != nil {
			return err
		}
		_, err = c.stream.Write(sealed)
		return err
	}, func(ctx context.Context, d time.Duration) error {
		started := time.Now()
		answered, err := awaitReply(ctx, c.stream, buf, d)
		c.statsMu.Lock()
		if answered {
			c.stats.StartupAnswered++
		}
		waited := time.Since(started)
		c.stats.StartupLongestWait = max(c.stats.StartupLongestWait, waited)
		if !answered {
			waited = -waited
		}
		c.stats.StartupWaits = append(c.stats.StartupWaits, waited)
		c.statsMu.Unlock()
		return err
	})
}

// deadlineReader is the part of a KCP conversation awaitReply reads.
type deadlineReader interface {
	SetReadDeadline(time.Time) error
	Read([]byte) (int, error)
}

// awaitReply waits at most d for one message on the control conversation:
// true when one came, false when d (or ctx) ran out first. The message itself
// is not needed; drainControl discards the later ones the same way.
func awaitReply(ctx context.Context, r deadlineReader, buf []byte, d time.Duration) (bool, error) {
	deadline := time.Now().Add(d)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := r.SetReadDeadline(deadline); err != nil {
		return false, err
	}
	if _, err := r.Read(buf); err != nil {
		var timeout interface{ Timeout() bool }
		if errors.As(err, &timeout) && timeout.Timeout() {
			return false, ctx.Err()
		}
		return false, err
	}
	return true, nil
}

func (c *Client) startupGap() time.Duration {
	switch {
	case c.StartupGap < 0:
		return 0
	case c.StartupGap == 0:
		return DefaultStartupGap
	}
	return c.StartupGap
}

// sendPaced sends msgs in order with gap between two of them, and none after
// the last: nothing follows it, so a pause there only delays the stream.
func sendPaced(ctx context.Context, msgs [][]byte, gap time.Duration, send func([]byte) error, wait func(context.Context, time.Duration) error) error {
	for i, msg := range msgs {
		if i > 0 && gap > 0 {
			if err := wait(ctx, gap); err != nil {
				return err
			}
		}
		if err := send(msg); err != nil {
			return err
		}
	}
	return nil
}

// maxKCPMessage bounds one message read from a kcp conversation. kcp hands a
// larger message out in pieces, and a piece of a sealed message cannot be
// opened; 512 KiB is well above a whole keyframe at 1080p.
const maxKCPMessage = 512 << 10

func (c *Client) readLoop(ctx context.Context, stream *kcp.UDPSession, aesKey []byte) {
	buf := make([]byte, maxKCPMessage)
	for {
		if ctx.Err() != nil {
			return
		}
		deadline := time.Now().Add(10 * time.Second)
		if c.MediaIdleTimeout > 0 {
			deadline = c.mediaDeadline()
		}
		if err := stream.SetReadDeadline(deadline); err != nil {
			return
		}
		n, err := stream.Read(buf)
		if err != nil {
			if isTimeout(err) {
				if c.MediaIdleTimeout > 0 && !time.Now().Before(c.mediaDeadline()) {
					c.fail(fmt.Errorf("%w for %v", ErrMediaIdle, c.MediaIdleTimeout))
					return
				}
				// Quiet for a while (audio paused, say, or another
				// conversation delivering): keep reading. Without
				// MediaIdleTimeout a video stall is the caller's to notice;
				// stopping here lost this conversation for the session.
				continue
			}
			debugf("tuyalan: %s media conversation ended: %v", c.DeviceID, err)
			return
		}
		c.count(&c.stats.Reads)
		msg, err := open(aesKey, buf[:n])
		if err != nil {
			c.count(&c.stats.OpenErrors)
			continue
		}
		cmd, ts, _, payload, ok := mediaPayload(msg)
		if !ok {
			c.count(&c.stats.Malformed)
			continue
		}
		c.markMedia()
		switch cmd {
		case CmdMediaVideo:
			c.count(&c.stats.Video)
			if c.onFrame != nil {
				c.onFrame(parseVideo(msg, ts, payload))
			}
		case CmdMediaAudio:
			c.count(&c.stats.Audio)
			if c.onAudio != nil {
				c.onAudio(parseAudio(msg, ts, payload))
			}
		default:
			c.countOther(cmd)
		}
	}
}

// drainControl reads and drops what the camera sends on the control
// conversation. Nothing here needs it, but unread messages stay queued in
// kcp, and after a window's worth (512) it advertises a zero window to the
// camera for the rest of the session. onControl, when set, is told each
// message's size.
func drainControl(ctx context.Context, control *kcp.UDPSession, onControl func(int)) {
	buf := make([]byte, maxKCPMessage)
	for ctx.Err() == nil {
		if err := control.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}
		n, err := control.Read(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return
		}
		if onControl != nil {
			onControl(n)
		}
	}
}

// keepAlive holds the signalling session open; the camera drops an idle one.
//
// That session is one of the camera's LAN sessions (an SCD951 serves three,
// measured 02-11-2026) for as long as the stream runs. It stays open on
// purpose: the camera ends a session over it (a disconnect signal or closing
// it), and whether it keeps sending media once the control connection is gone
// was never tested. Count it toward the camera's session budget.
func (c *Client) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.session.Heartbeat(); err != nil {
				c.fail(fmt.Errorf("tuyalan: heartbeat: %w", err))
				return
			}
		}
	}
}

// watchControl reads the control connection for as long as the session runs.
// It drains the heartbeat replies and notices the camera ending the session,
// either by a disconnect signal or by closing the connection.
func (c *Client) watchControl(ctx context.Context) {
	for ctx.Err() == nil {
		h, payload, err := c.session.Recv(3 * HeartbeatInterval)
		if errors.Is(err, ErrAuth) {
			continue
		}
		if err != nil {
			c.fail(fmt.Errorf("tuyalan: control connection: %w", err))
			return
		}
		if h.Cmd != CmdIPCLan302 {
			c.handleData(h.Cmd, payload, time.Now())
			continue
		}
		frame := parseSignal(c.session, payload)
		ends, foreign := endsSession(frame, c.sessionID)
		if foreign {
			debugf("tuyalan: %s ignored a disconnect for session %s (ours %s)", c.DeviceID, frame.Header.SessionID, c.sessionID)
			continue
		}
		if ends {
			c.fail(ErrCameraEnded)
			return
		}
	}
}

// handleData passes a status push on to OnDPS and hands a command's answer to
// the command waiting for it. A query answer is also a full set of points, so
// it goes to OnDPS too.
func (c *Client) handleData(cmd uint32, payload []byte, at time.Time) {
	switch cmd {
	case CmdStatus, CmdDPQueryNew, CmdControlNew, CmdControl33, CmdDPQuery33:
	default:
		return
	}
	dps, ok := ParseDPS(payload)
	c.waitMu.Lock()
	if c.waitDone != nil && c.waitCmd == cmd {
		if !ok {
			dps = map[string]any{}
		}
		select {
		case c.waitDone <- dps:
		default:
		}
		c.waitDone = nil
	}
	c.waitMu.Unlock()
	if ok && cmd != CmdControlNew && cmd != CmdControl33 && c.OnDPS != nil {
		c.OnDPS(dps, at)
	}
}

// ErrNoSession is returned by SetDPS and QueryDPS without a running session.
var ErrNoSession = errors.New("tuyalan: no running session")

// SetDPS sets data points over the control connection and waits for the
// camera's answer. One command at a time; the camera's push of the new
// values follows separately through OnDPS.
func (c *Client) SetDPS(ctx context.Context, dps map[string]any) error {
	if !ValidDPS(dps) {
		return errors.New("tuyalan: invalid data points")
	}
	if c.sessionVersion() == V33 {
		payload, err := controlPayload33(c.DeviceID, dps, time.Now())
		if err != nil {
			return err
		}
		_, err = c.exchange(ctx, CmdControl33, payload)
		return err
	}
	payload, err := controlPayload(dps, time.Now())
	if err != nil {
		return err
	}
	_, err = c.exchange(ctx, CmdControlNew, payload)
	return err
}

// QueryDPS asks the camera for all its data points.
func (c *Client) QueryDPS(ctx context.Context) (map[string]any, error) {
	if c.sessionVersion() == V33 {
		payload, err := queryPayload33(c.DeviceID, time.Now())
		if err != nil {
			return nil, err
		}
		return c.exchange(ctx, CmdDPQuery33, payload)
	}
	return c.exchange(ctx, CmdDPQueryNew, queryPayload())
}

// sessionVersion is the running session's protocol, 0 without one.
func (c *Client) sessionVersion() Version {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return 0
	}
	return c.session.Version
}

func (c *Client) exchange(ctx context.Context, cmd uint32, payload []byte) (map[string]any, error) {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()
	c.mu.Lock()
	session, closed, running := c.session, c.closed, c.stopLife != nil
	c.mu.Unlock()
	if session == nil || closed || !running {
		return nil, ErrNoSession
	}
	done := make(chan map[string]any, 1)
	c.waitMu.Lock()
	c.waitCmd, c.waitDone = cmd, done
	c.waitMu.Unlock()
	defer func() {
		c.waitMu.Lock()
		if c.waitDone == done {
			c.waitDone = nil
		}
		c.waitMu.Unlock()
	}()
	if err := session.SendCommand(cmd, payload); err != nil {
		return nil, err
	}
	select {
	case dps := <-done:
		return dps, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// fail reports the end of a running session once, unless Close got there first.
func (c *Client) fail(err error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	c.failed.Do(func() {
		if c.OnError != nil {
			c.OnError(err)
		}
	})
}

// Close tears the session down.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.stopLife != nil {
		c.stopLife()
	}
	if c.stream != nil {
		c.stream.Close()
	}
	for _, m := range c.media {
		m.Close()
	}
	if c.cloud != nil {
		// Tells the camera to drop the session before the next one starts.
		_ = c.cloud.Close()
	}
	if c.sock != nil {
		c.sock.Close()
	}
	if c.session != nil {
		return c.session.Close()
	}
	return nil
}

func sdpAttr(sdp, name string) string {
	// CRLF, or a bare LF from a sender that uses one.
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "a="+name+":") {
			return strings.TrimPrefix(line, "a="+name+":")
		}
	}
	return ""
}

func parseCandidate(line string) (*net.UDPAddr, error) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "a="))
	m := candidateRE.FindStringSubmatch(line)
	if m == nil {
		return nil, errors.New("tuyalan: unusable candidate")
	}
	ip := net.ParseIP(m[5])
	if ip == nil {
		return nil, errors.New("tuyalan: candidate carries no address")
	}
	port, err := strconv.Atoi(m[6])
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}
