package tuyalan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fakeKey = "fake-local-key!!"

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]Version{"": 0, "auto": 0, "3.3": V33, "3.4": V34, " 3.5 ": V35} {
		got, err := ParseVersion(in)
		if err != nil || got != want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseVersion("3.1"); err == nil {
		t.Error("3.1 is not spoken here, it must be refused")
	}
}

func TestVersionOrder(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		configured, remember Version
		want                 []Version
	}{
		{"nothing known", 0, 0, []Version{V35, V34}},
		{"configured 3.4 first, 3.5 as fallback", V34, 0, []Version{V34, V35}},
		{"remembered 3.4", 0, V34, []Version{V34, V35}},
		{"configured wins over remembered", V35, V34, []Version{V35, V34}},
		{"unknown values are dropped", Version(32), 0, []Version{V35, V34}},
		// 3.3 proves no key in a handshake: only when configured (a camera bound
		// to one address), and then alone; never as a fallback or a memory.
		{"configured 3.3 is the only version", V33, V34, []Version{V33}},
		{"remembered 3.3 is not tried", 0, V33, []Version{V35, V34}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := VersionOrder(tc.configured, tc.remember)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestHostPort(t *testing.T) {
	if got := HostPort("192.0.2.7"); got != "192.0.2.7:6668" {
		t.Fatalf("got %q", got)
	}
	if got := HostPort("192.0.2.7:1234"); got != "192.0.2.7:1234" {
		t.Fatalf("got %q", got)
	}
}

// silent accepts a connection and never says a word, like a camera asked
// for the wrong protocol version.
func silent(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) }

func TestDialGivesUpOnASilentCamera(t *testing.T) {
	addr := listen(t, silent)
	for _, v := range []Version{V34, V35} {
		started := time.Now()
		_, err := Dial(context.Background(), DialConfig{
			Addr: addr, LocalKey: fakeKey, Version: v, HandshakeTimeout: 300 * time.Millisecond,
		})
		if err == nil {
			t.Fatalf("%s: a camera that never answers completed a handshake", v)
		}
		if took := time.Since(started); took > 2*time.Second {
			t.Fatalf("%s: Dial took %s against a silent camera, the deadline is 300ms", v, took)
		}
	}
}

func TestDialHonoursTheContextDeadline(t *testing.T) {
	addr := listen(t, silent)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	// The default handshake timeout is five seconds; the context is shorter.
	if _, err := Dial(ctx, DialConfig{Addr: addr, LocalKey: fakeKey, Version: V34}); err == nil {
		t.Fatal("handshake completed against a silent camera")
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("Dial took %s, the context allowed 300ms", took)
	}
}

func TestStartGivesUpOnASilentCamera(t *testing.T) {
	addr := listen(t, silent)
	c := NewClient("fakedevice", fakeKey, "fake-password", "fake-uid", []string{addr}, []Version{V35, V34}, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := c.Start(ctx); err == nil {
		t.Fatal("Start succeeded against a silent camera")
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("Start took %s, the context allowed 700ms", took)
	}
}

// fakeCamera34 answers the 3.4 negotiation under key and ignores anything
// framed as 6699, which is how the SCD951 treated a 3.5 attempt.
func fakeCamera34(key string) func(net.Conn) {
	return func(conn net.Conn) {
		head, err := readExactly(conn, header55AALen)
		if err != nil {
			return
		}
		if binary.BigEndian.Uint32(head[:4]) != Prefix55AA {
			silent(conn)
			return
		}
		h, err := ParseHeader(head)
		if err != nil {
			return
		}
		rest, err := readExactly(conn, h.Total-header55AALen)
		if err != nil {
			return
		}
		_, nonce, err := Unpack55AA34([]byte(key), append(head, rest...))
		if err != nil {
			return
		}
		remote := bytes.Repeat([]byte{0x5a}, nonceLen)
		reply, _ := pack55AA34([]byte(key), 1, CmdSessKeyNegResp, append(remote, hmacSHA256([]byte(key), nonce)...), true)
		_, _ = conn.Write(reply)
		silent(conn)
	}
}

func TestConnectFallsBackFrom35To34(t *testing.T) {
	addr := listen(t, fakeCamera34(fakeKey))
	c := NewClient("fakedevice", fakeKey, "", "", []string{addr}, VersionOrder(0, 0), nil, nil)
	c.ProbeTimeout = 200 * time.Millisecond
	started := time.Now()
	s, err := c.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if c.Version != V34 || s.Version != V34 {
		t.Fatalf("connected with %s, want 3.4", c.Version)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("the 3.5 probe was not cut short: connect took %s", took)
	}
}

// With a list of addresses each camera keeps the one whose handshake proves
// its key, so another camera of the account is passed over.
func TestConnectSkipsACameraWithAnotherKey(t *testing.T) {
	other := listen(t, fakeCamera34("other-fake-key!!"))
	ours := listen(t, fakeCamera34(fakeKey))
	c := NewClient("fakedevice", fakeKey, "", "", []string{other, ours}, []Version{V34}, nil, nil)
	s, err := c.connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if c.Host != ours {
		t.Fatalf("connected to %s, want %s", c.Host, ours)
	}
}

func dialFake(t *testing.T, serve func(net.Conn)) *Session {
	t.Helper()
	addr := listen(t, func(conn net.Conn) {
		fakeCamera34(fakeKey)(&scripted{Conn: conn, after: serve})
	})
	s, err := Dial(context.Background(), DialConfig{Addr: addr, LocalKey: fakeKey, Version: V34})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// scripted hands the connection to after once the negotiation reply is out.
type scripted struct {
	net.Conn
	after  func(net.Conn)
	writes int
}

func (s *scripted) Write(p []byte) (int, error) {
	n, err := s.Conn.Write(p)
	s.writes++
	if s.writes == 1 && s.after != nil {
		go s.after(s.Conn)
	}
	return n, err
}

// A length field past maxFrameLen is skipped like a bad prefix: the next real
// frame still comes through, and the buffer stays bounded meanwhile (the fork
// kept reading for that frame and grew its buffer without bound).
func TestRecvResyncsPastAnImplausibleLength(t *testing.T) {
	var key []byte
	ready := make(chan struct{})
	s := dialFake(t, func(conn net.Conn) {
		<-ready
		head := make([]byte, header55AALen)
		binary.BigEndian.PutUint32(head[0:4], Prefix55AA)
		binary.BigEndian.PutUint32(head[8:12], CmdIPCLan302)
		binary.BigEndian.PutUint32(head[12:16], 0x7fffffff)
		_, _ = conn.Write(head)
		_, _ = conn.Write(bytes.Repeat([]byte{0xee}, 256*1024))
		frame, _ := pack55AA34(key, 2, CmdIPCLan302, []byte(`{"header":{"type":"answer"}}`), true)
		_, _ = conn.Write(frame)
	})
	key = s.Key
	close(ready)
	h, plain, err := s.Recv(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if h.Cmd != CmdIPCLan302 || !bytes.Contains(plain, []byte("answer")) {
		t.Fatalf("got cmd %d %q", h.Cmd, plain)
	}
	if len(s.readBuf) > readChunk {
		t.Fatalf("read buffer holds %d bytes after the garbage", len(s.readBuf))
	}
}

// Garbage without a prefix is thrown away as it arrives, so the buffer stays
// small and the next real frame is still found.
func TestRecvBufferStaysBoundedOnGarbage(t *testing.T) {
	var key []byte
	ready := make(chan struct{})
	s := dialFake(t, func(conn net.Conn) {
		<-ready
		_, _ = conn.Write(bytes.Repeat([]byte{0xee}, 4*maxReadBuffer))
		frame, _ := pack55AA34(key, 2, CmdIPCLan302, []byte(`{"header":{"type":"answer"}}`), true)
		_, _ = conn.Write(frame)
	})
	key = s.Key
	close(ready)
	h, plain, err := s.Recv(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if h.Cmd != CmdIPCLan302 || !bytes.Contains(plain, []byte("answer")) {
		t.Fatalf("got cmd %d %q", h.Cmd, plain)
	}
	if len(s.readBuf) > readChunk {
		t.Fatalf("read buffer holds %d bytes after the garbage", len(s.readBuf))
	}
}

// The SCD951 sends two candidates; the one on the address the TCP session
// reached is the one to check, whichever comes first.
func TestCollectAnswerPrefersTheCandidateOnTheSessionAddress(t *testing.T) {
	var key []byte
	ready := make(chan struct{})
	s := dialFake(t, func(conn net.Conn) {
		<-ready
		sdp := "v=0\r\na=ice-ufrag:wxyz\r\na=ice-pwd:nmlkjihgfedcba9876543210\r\na=aes-key:" +
			"30313233343536373839616263646566\r\n"
		for _, body := range []string{
			`{"header":{"type":"answer","path":"lan"},"msg":{"sdp":"` + jsonEscape(sdp) + `"}}`,
			`{"header":{"type":"candidate","path":"lan"},"msg":{"candidate":"a=candidate:1 1 UDP 2130706431 192.0.2.99 40001 typ host\r\n"}}`,
			`{"header":{"type":"candidate","path":"lan"},"msg":{"candidate":"a=candidate:2 1 UDP 2130706431 127.0.0.1 40002 typ host\r\n"}}`,
		} {
			frame, _ := pack55AA34(key, 2, CmdIPCLan302, []byte(body), true)
			_, _ = conn.Write(frame)
		}
	})
	key = s.Key
	close(ready)

	c := &Client{session: s}
	remote, aesKey, peer, err := c.collectAnswer(context.Background(), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if remote.Ufrag != "wxyz" || string(aesKey) != "0123456789abcdef" {
		t.Fatalf("answer parsed as %+v / %q", remote, aesKey)
	}
	if peer.Port != 40002 {
		t.Fatalf("checking %s, want the candidate on 127.0.0.1", peer)
	}
}

func jsonEscape(s string) string {
	return strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(s)
}

// fakeCameraReplyingUnder answers a 3.4 negotiation under its own key without
// checking ours: a camera with another key that still replies.
func fakeCameraReplyingUnder(key string, conns *atomic.Int32) func(net.Conn) {
	return func(conn net.Conn) {
		conns.Add(1)
		head, err := readExactly(conn, header55AALen)
		if err != nil || binary.BigEndian.Uint32(head[:4]) != Prefix55AA {
			silent(conn)
			return
		}
		h, err := ParseHeader(head)
		if err != nil {
			return
		}
		if _, err := readExactly(conn, h.Total-header55AALen); err != nil {
			return
		}
		reply, _ := pack55AA34([]byte(key), 1, CmdSessKeyNegResp, bytes.Repeat([]byte{0x5a}, nonceLen+32), true)
		_, _ = conn.Write(reply)
		silent(conn)
	}
}

func TestAReplyUnderAnotherKeyIsAWrongKey(t *testing.T) {
	var conns atomic.Int32
	addr := listen(t, fakeCameraReplyingUnder("other-fake-key!!", &conns))
	_, err := Dial(context.Background(), DialConfig{Addr: addr, LocalKey: fakeKey, Version: V34, HandshakeTimeout: time.Second})
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestACameraWithAnotherKeyIsNotProbedAtTheOtherVersion(t *testing.T) {
	var conns atomic.Int32
	addr := listen(t, fakeCameraReplyingUnder("other-fake-key!!", &conns))
	c := NewClient("fakedevice", fakeKey, "", "", []string{addr}, []Version{V34, V35}, nil, nil)
	c.ProbeTimeout = 200 * time.Millisecond
	if _, err := c.connect(context.Background()); err == nil {
		t.Fatal("connected to a camera with another key")
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("%d connections, want 1: no 3.5 probe after a wrong key", n)
	}
}

func TestTheSessionIsIPv4Only(t *testing.T) {
	_, err := Dial(context.Background(), DialConfig{Addr: "::1", LocalKey: fakeKey, Version: V34, HandshakeTimeout: 200 * time.Millisecond})
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Fatalf("got %v, want a dial error for an IPv6 address", err)
	}
}

// A start that its context ends keeps the step it stopped at visible to
// errors.Is, next to the context's end (thekoma/aventproxy 38ff88f).
func TestStartEndedKeepsTheStep(t *testing.T) {
	cloud := newFakeCloud()
	c := NewClient("dev", "fake-local-key-0", "", "uid", nil, nil, nil, nil)
	c.Signaller = cloud
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		cloud.await(2 * time.Second)
		cancel()
	}()
	err := c.Start(ctx)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("err = %v, want both the cancellation and ErrNoAnswer", err)
	}
}
