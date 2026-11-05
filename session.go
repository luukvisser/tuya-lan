package tuyalan

// Ported from Leonard Pitzu's leonardpitzu/aventproxy (MIT). Changed here:
// protocol 3.4 next to 3.5, a deadline on every handshake read and write, and a
// bounded read buffer.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Port is the Tuya LAN control channel.
	Port = 6668

	// HeartbeatInterval keeps the socket alive: the camera closes an idle
	// connection after roughly 30-45 seconds.
	HeartbeatInterval = 8 * time.Second

	// DefaultDialTimeout bounds the TCP connect.
	DefaultDialTimeout = 3 * time.Second
	// DefaultHandshakeTimeout bounds the whole session-key negotiation. A
	// camera on the LAN answers it in milliseconds.
	DefaultHandshakeTimeout = 5 * time.Second
	// ProbeHandshakeTimeout is used when a version is only being tried. An
	// SCD951, which speaks 3.4 only, stays silent for ten seconds before it
	// drops a 3.5 negotiation (measured 01-11-2026), so waiting that out would
	// cost every stream start ten seconds.
	ProbeHandshakeTimeout = 3 * time.Second

	ioTimeout = 10 * time.Second
	nonceLen  = 16

	// maxReadBuffer caps what Recv holds while it waits for a frame to
	// complete: two of the largest frames ParseHeader accepts. Anything beyond
	// that means the stream is desynced, and the session is dropped instead of
	// growing the buffer without end.
	maxReadBuffer = 2 * (maxFrameLen + header6699Len + suffixLen)
	readChunk     = 16 * 1024
)

var (
	// ErrBufferOverflow is returned once the read buffer would pass
	// maxReadBuffer.
	ErrBufferOverflow = errors.New("tuyalan: read buffer overflow, stream desynced")
	// ErrWrongKey means the camera answered the negotiation but not under our
	// localKey: it is another device, or the key is stale.
	ErrWrongKey = errors.New("tuyalan: negotiation HMAC mismatch, wrong localKey")
)

// Version is a Tuya LAN protocol version this package speaks.
type Version int

const (
	// V33 has no key negotiation, so a handshake proves nothing; Dial asks
	// for the data points first and keeps the session only when the answer
	// decrypts under the camera's key. Never tried unless configured.
	V33 Version = 33
	V34 Version = 34
	V35 Version = 35
)

func (v Version) String() string {
	return fmt.Sprintf("%d.%d", int(v)/10, int(v)%10)
}

// DefaultVersions is the order versions are tried in when none is known: 3.5
// first, which the SCD973 the protocol was worked out on speaks, then 3.4 for
// the SCD951.
var DefaultVersions = []Version{V35, V34}

// ParseVersion reads "3.3", "3.4" or "3.5". An empty string or "auto" gives 0,
// which means "not known".
func ParseVersion(s string) (Version, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return 0, nil
	case "3.3":
		return V33, nil
	case "3.4":
		return V34, nil
	case "3.5":
		return V35, nil
	default:
		return 0, fmt.Errorf("tuyalan: unsupported protocol version %q (want 3.3, 3.4 or 3.5)", s)
	}
}

// VersionOrder lists the versions to try: the configured one first, then one
// that worked earlier in this process, then the rest of DefaultVersions. The
// configured one is a preference, not a limit, so a wrong value costs time
// rather than the local path. 3.3 is the exception: configured, it is the only
// version tried (configure it only for a camera at a known address that speaks
// nothing newer), and never tried otherwise.
func VersionOrder(configured, remembered Version) []Version {
	if configured == V33 {
		return []Version{V33}
	}
	out := make([]Version, 0, len(DefaultVersions))
	add := func(v Version) {
		for _, have := range out {
			if have == v {
				return
			}
		}
		for _, known := range DefaultVersions {
			if known == v {
				out = append(out, v)
				return
			}
		}
	}
	add(configured)
	add(remembered)
	for _, v := range DefaultVersions {
		add(v)
	}
	return out
}

// HostPort adds the LAN port to a host that has none. Tests pass host:port.
func HostPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(Port))
}

// DialConfig describes one connection attempt.
type DialConfig struct {
	// Addr is the camera's address, with or without a port.
	Addr     string
	LocalKey string
	Version  Version
	// DeviceID is what a 3.3 session's first answer must not contradict; see
	// Dial. Unused by 3.4 and 3.5, whose negotiation proves the key.
	DeviceID string
	// DialTimeout and HandshakeTimeout default to DefaultDialTimeout and
	// DefaultHandshakeTimeout.
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// Rand supplies the nonces; nil means crypto/rand. Tests pin it.
	Rand io.Reader
}

// Session is an authenticated LAN connection to one camera.
type Session struct {
	Version Version
	Key     []byte // session key, derived during the handshake

	conn    net.Conn
	rand    io.Reader
	seq     atomic.Uint32
	readBuf []byte

	readMu  sync.Mutex
	writeMu sync.Mutex

	// lan302Header puts the 3.3 version header in front of command 32 on a
	// 3.3 session. Unmeasured: 3.4 wanted none (the SCD951 stayed silent with
	// it), so the default is without and Client.Start tries once with it.
	lan302Header bool
}

// Dial opens a connection and completes the session-key negotiation for
// cfg.Version. Every read and write of the handshake runs under one deadline,
// which ctx can shorten or cancel: a camera that accepts the connection and
// then never answers costs at most HandshakeTimeout.
//
// A completed negotiation proves the camera holds LocalKey, since its reply
// carries an HMAC under that key. A caller with several candidate addresses
// can therefore try each and keep the one that completes.
func Dial(ctx context.Context, cfg DialConfig) (*Session, error) {
	if len(cfg.LocalKey) != 16 {
		return nil, fmt.Errorf("tuyalan: localKey must be 16 bytes, got %d", len(cfg.LocalKey))
	}
	if cfg.Version != V33 && cfg.Version != V34 && cfg.Version != V35 {
		return nil, fmt.Errorf("tuyalan: unsupported protocol version %s", cfg.Version)
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	handshakeTimeout := cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = DefaultHandshakeTimeout
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	// IPv4 only, like the media socket and its ICE candidate (Start,
	// localAddrFor): a session on IPv6 would hand over and then never get
	// video. A host name resolves to its IPv4 address; an IPv6 literal fails
	// here at once and the next host is tried.
	conn, err := dialer.DialContext(ctx, "tcp4", HostPort(cfg.Addr))
	if err != nil {
		return nil, fmt.Errorf("tuyalan: dial: %w", err)
	}

	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	// A cancelled context interrupts a handshake that is blocked in a read.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })

	s := &Session{Version: cfg.Version, conn: conn, rand: cfg.Rand}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	if cfg.Version == V33 {
		err = s.prove33([]byte(cfg.LocalKey), cfg.DeviceID)
	} else {
		err = s.negotiate([]byte(cfg.LocalKey))
	}
	if !stop() || ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if err == nil {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tuyalan: %s handshake: %w", cfg.Version, err)
	}
	return s, nil
}

// negotiate performs SESS_KEY_NEG start/response/finish and installs the key.
// Both versions run the same exchange; they differ in framing and in how the
// key is derived from the two nonces.
func (s *Session) negotiate(localKey []byte) error {
	localNonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(s.rand, localNonce); err != nil {
		return err
	}

	if err := s.sendWithKey(localKey, CmdSessKeyNegStart, localNonce); err != nil {
		return fmt.Errorf("neg start: %w", err)
	}

	h, payload, err := s.recvWithKey(localKey)
	if err != nil {
		if errors.Is(err, ErrAuth) && h.Prefix == framingPrefix(s.Version) {
			// This version is spoken here, but the reply does not open under
			// our key: a camera with another key. Trying the other version
			// there would only cost a handshake timeout.
			return fmt.Errorf("neg response: %w: %w", ErrWrongKey, err)
		}
		return fmt.Errorf("neg response: %w", err)
	}
	if h.Cmd != CmdSessKeyNegResp {
		return fmt.Errorf("expected cmd %d, got %d", CmdSessKeyNegResp, h.Cmd)
	}
	if s.Version == V35 {
		// 6699 frames from the camera carry a retcode inside the encryption;
		// the nonce sits behind it. 3.4 keeps the retcode outside, and
		// Unpack55AA34 has already taken it off.
		payload = StripRetcode(payload)
	}
	if len(payload) < nonceLen+sha256.Size {
		return errors.New("negotiation response too short")
	}
	remoteNonce := payload[:nonceLen]

	want := hmacSHA256(localKey, localNonce)
	if !hmac.Equal(want, payload[nonceLen:nonceLen+sha256.Size]) {
		return ErrWrongKey
	}

	if err := s.sendWithKey(localKey, CmdSessKeyNegFinish, hmacSHA256(localKey, remoteNonce)); err != nil {
		return fmt.Errorf("neg finish: %w", err)
	}

	key, err := sessionKey(s.Version, localKey, localNonce, remoteNonce)
	if err != nil {
		return err
	}
	s.Key = key
	return nil
}

// prove33 stands in for the negotiation 3.3 lacks. Anyone can complete a 3.3
// "handshake", so before anything else the session asks for the data points
// (command 10, as tinytuya does) and accepts only an answer that decrypts
// under localKey into JSON and names no other device. Two unreadable frames,
// or a foreign devId, is ErrWrongKey: another device at that address, which
// must never get the offer.
//
// A camera with a 22-character id may answer command 10 with the text "json
// obj data unvalid" instead of JSON (tinytuya's "device22", localtuya's
// "type 0d"): an SCD973-family unit did, 11 ms after the query, 02-11-2026.
// That text decrypted under localKey, which no other device's key yields, so
// it proves the camera as well as JSON would.
func (s *Session) prove33(localKey []byte, deviceID string) error {
	s.Key = localKey
	query, err := json.Marshal(map[string]string{
		"gwId": deviceID, "devId": deviceID, "uid": deviceID,
		"t": strconv.FormatInt(time.Now().Unix(), 10),
	})
	if err != nil {
		return err
	}
	if err := s.send(localKey, CmdDPQuery33, nil, query); err != nil {
		return err
	}
	unreadable := 0
	for {
		_, payload, err := s.recvWithKey(localKey)
		if err != nil {
			if !errors.Is(err, ErrAuth) {
				return err
			}
			payload = []byte{0}
		}
		if len(payload) == 0 {
			// An acknowledgement: no proof either way.
			continue
		}
		if bytes.Contains(payload, []byte("data unvalid")) {
			return nil
		}
		var doc map[string]any
		if json.Unmarshal(bytes.TrimSpace(payload), &doc) != nil {
			unreadable++
			if unreadable >= 2 {
				return fmt.Errorf("%w: two answers that do not decrypt under it", ErrWrongKey)
			}
			continue
		}
		if id, ok := doc["devId"].(string); ok && deviceID != "" && id != deviceID {
			return fmt.Errorf("%w: the answer names another device", ErrWrongKey)
		}
		return nil
	}
}

// sessionKey mirrors tinytuya and the SDK: encrypt the XOR of both nonces
// under the localKey and keep 16 bytes of the result. 3.4 uses one AES-ECB
// block; 3.5 uses GCM with the local nonce as IV.
func sessionKey(v Version, localKey, localNonce, remoteNonce []byte) ([]byte, error) {
	mixed := make([]byte, nonceLen)
	for i := range mixed {
		mixed[i] = localNonce[i] ^ remoteNonce[i]
	}
	block, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	if v == V34 {
		out := make([]byte, nonceLen)
		block.Encrypt(out, mixed)
		return out, nil
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmIVLen)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, localNonce[:gcmIVLen], mixed, nil)
	return sealed[:nonceLen], nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Send encrypts and writes a frame under the session key.
//
// iv is used by 3.5 only and must be an ASCII UUID fragment for command 32;
// see Pack6699. 3.4 frames carry no IV.
func (s *Session) Send(cmd uint32, iv, payload []byte) error {
	return s.send(s.Key, cmd, iv, payload)
}

func (s *Session) sendWithKey(key []byte, cmd uint32, payload []byte) error {
	var iv []byte
	if s.Version == V35 {
		iv = make([]byte, gcmIVLen)
		if _, err := io.ReadFull(s.rand, iv); err != nil {
			return err
		}
	}
	return s.send(key, cmd, iv, payload)
}

func (s *Session) send(key []byte, cmd uint32, iv, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var frame []byte
	var err error
	switch s.Version {
	case V33:
		header := !noVersionHeader33[cmd]
		if cmd == CmdIPCLan302 {
			header = s.lan302Header
		}
		frame, err = Pack55AA33(key, s.seq.Add(1), cmd, payload, header)
	case V34:
		body := append(append([]byte{}, versionHeader(cmd)...), payload...)
		frame, err = Pack55AA34(key, s.seq.Add(1), cmd, body)
	default:
		frame, err = Pack6699(key, iv, s.seq.Add(1), cmd, payload)
	}
	if err != nil {
		return err
	}
	// Dial's handshake deadline is already on the connection; a later write
	// gets its own.
	if s.Key != nil {
		if err := s.conn.SetWriteDeadline(time.Now().Add(ioTimeout)); err != nil {
			return err
		}
	}
	_, err = s.conn.Write(frame)
	return err
}

// Recv reads the next frame, decrypted under the session key. An error
// wrapping ErrAuth leaves the stream usable; any other error means the
// session should be closed.
func (s *Session) Recv(timeout time.Duration) (Header, []byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if err := s.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return Header{}, nil, err
	}
	return s.recvWithKey(s.Key)
}

func (s *Session) recvWithKey(key []byte) (Header, []byte, error) {
	for {
		// Serve a complete frame out of the buffer before reading more.
		h, err := ParseHeader(s.readBuf)
		switch {
		case err == nil && len(s.readBuf) >= h.Total:
			frame := s.readBuf[:h.Total]
			s.readBuf = s.readBuf[h.Total:]
			return s.unpack(key, h, frame)
		case errors.Is(err, ErrBadPrefix), errors.Is(err, ErrBadLength):
			// Resynchronise on the next plausible prefix rather than giving up,
			// keeping a tail that may hold the start of one. A length past
			// maxFrameLen is a desynced stream too: the fork waited for that
			// frame and grew its buffer without bound, and ending the session
			// over it (as this module did) lost a session a later frame would
			// have carried on (thekoma/aventproxy b5b369a). The buffer stays
			// bounded by maxReadBuffer either way.
			if idx := nextPrefix(s.readBuf); idx > 0 {
				s.readBuf = s.readBuf[idx:]
				continue
			}
			if len(s.readBuf) > 3 {
				s.readBuf = append([]byte{}, s.readBuf[len(s.readBuf)-3:]...)
			}
		}

		if len(s.readBuf)+readChunk > maxReadBuffer {
			s.readBuf = nil
			return Header{}, nil, ErrBufferOverflow
		}
		chunk := make([]byte, readChunk)
		n, err := s.conn.Read(chunk)
		if n > 0 {
			s.readBuf = append(s.readBuf, chunk[:n]...)
		}
		if err != nil {
			return Header{}, nil, err
		}
	}
}

func (s *Session) unpack(key []byte, h Header, frame []byte) (Header, []byte, error) {
	switch {
	case s.Version == V33 && h.Prefix == Prefix55AA:
		return Unpack55AA33(key, frame)
	case s.Version == V34 && h.Prefix == Prefix55AA:
		return Unpack55AA34(key, frame)
	case s.Version == V35 && h.Prefix == Prefix6699:
		return Unpack6699(key, frame)
	default:
		// Whole, but in the other version's format: nothing we can open.
		return h, nil, fmt.Errorf("%w: cmd %d in %08X framing on a %s session", ErrAuth, h.Cmd, h.Prefix, s.Version)
	}
}

// framingPrefix is the frame prefix a session of version v sends and expects.
func framingPrefix(v Version) uint32 {
	if v == V35 {
		return Prefix6699
	}
	return Prefix55AA
}

func nextPrefix(buf []byte) int {
	for i := 1; i+4 <= len(buf); i++ {
		switch binary.BigEndian.Uint32(buf[i : i+4]) {
		case Prefix6699, Prefix55AA:
			return i
		}
	}
	return -1
}

// SendCommand writes a command frame under the session key, with a fresh IV
// on 3.5.
func (s *Session) SendCommand(cmd uint32, payload []byte) error {
	return s.sendWithKey(s.Key, cmd, payload)
}

// Heartbeat pings the camera so it does not drop an idle session. On 3.3 the
// body is "{}", as tinytuya sends it.
func (s *Session) Heartbeat() error {
	if s.Version == V33 {
		return s.sendWithKey(s.Key, CmdHeartbeat, []byte("{}"))
	}
	return s.sendWithKey(s.Key, CmdHeartbeat, nil)
}

// SetLan302Header chooses whether command 32 carries the version header on a
// 3.3 session (see lan302Header).
func (s *Session) SetLan302Header(on bool) {
	s.writeMu.Lock()
	s.lan302Header = on
	s.writeMu.Unlock()
}

// RemoteAddr is the camera's address on this connection.
func (s *Session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

// Close shuts the connection down.
func (s *Session) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}
