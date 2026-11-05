package tuyalan

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// vectors34 are frames tinytuya 1.20.0 produced for a fake key and pinned
// nonces; testdata/gen_tinytuya34.py regenerates them. Matching them byte for
// byte is what says the Go framing is the one the camera accepted from
// tinytuya.
type vectors34 struct {
	LocalKey     string `json:"local_key"`
	LocalNonce   string `json:"local_nonce"`
	RemoteNonce  string `json:"remote_nonce"`
	NegStart     string `json:"neg_start"`
	NegResp      string `json:"neg_resp"`
	NegFinish    string `json:"neg_finish"`
	SessionKey   string `json:"session_key"`
	HeartbeatSeq uint32 `json:"heartbeat_seq"`
	Heartbeat    string `json:"heartbeat"`
	ControlBody  string `json:"control_body"`
	ControlSeq   uint32 `json:"control_seq"`
	Control      string `json:"control"`
	SignalBody   string `json:"signal_body"`
	SignalSeq    uint32 `json:"signal_seq"`
	Signal       string `json:"signal"`
	WithHeader   string `json:"signal_with_header"`
	AnswerBody   string `json:"answer_body"`
	Answer       string `json:"answer"`
}

func loadVectors34(t *testing.T) vectors34 {
	t.Helper()
	raw, err := os.ReadFile("testdata/tinytuya34.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors34
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertFrame(t *testing.T, name string, got []byte, err error, want []byte) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from tinytuya:\n got %x\nwant %x", name, got, want)
	}
}

func TestPack55AA34MatchesTinytuya(t *testing.T) {
	v := loadVectors34(t)
	key := []byte(v.LocalKey)
	session := unhex(t, v.SessionKey)

	got, err := Pack55AA34(key, 1, CmdSessKeyNegStart, unhex(t, v.LocalNonce))
	assertFrame(t, "neg start", got, err, unhex(t, v.NegStart))

	got, err = Pack55AA34(session, v.HeartbeatSeq, CmdHeartbeat, versionHeader(CmdHeartbeat))
	assertFrame(t, "heartbeat", got, err, unhex(t, v.Heartbeat))

	// Commands outside the exception list keep tinytuya's version header.
	got, err = Pack55AA34(session, v.ControlSeq, 7, append(versionHeader(7), v.ControlBody...))
	assertFrame(t, "control", got, err, unhex(t, v.Control))
}

// Command 32 goes without the version header: the SCD951 ignored the offer
// with it and answered at once without it.
func TestCommand32HasNoVersionHeader(t *testing.T) {
	v := loadVectors34(t)
	session := unhex(t, v.SessionKey)

	if h := versionHeader(CmdIPCLan302); h != nil {
		t.Fatalf("command 32 gets a %d-byte version header", len(h))
	}
	got, err := Pack55AA34(session, v.SignalSeq, CmdIPCLan302, append(versionHeader(CmdIPCLan302), v.SignalBody...))
	assertFrame(t, "signal", got, err, unhex(t, v.Signal))

	// tinytuya's own encoding adds the header; that is the frame the camera
	// stayed silent to, and it is not what we send.
	got, err = Pack55AA34(session, v.SignalSeq+1, CmdIPCLan302, append(append([]byte{}, versionHeader34...), v.SignalBody...))
	assertFrame(t, "signal with header", got, err, unhex(t, v.WithHeader))
}

func TestUnpack55AA34DeviceFrames(t *testing.T) {
	v := loadVectors34(t)
	key := []byte(v.LocalKey)

	h, plain, err := Unpack55AA34(key, unhex(t, v.NegResp))
	if err != nil {
		t.Fatal(err)
	}
	if h.Cmd != CmdSessKeyNegResp || len(plain) != 48 {
		t.Fatalf("neg response: cmd %d, %d bytes", h.Cmd, len(plain))
	}
	if !bytes.Equal(plain[:16], unhex(t, v.RemoteNonce)) {
		t.Fatalf("remote nonce = %x", plain[:16])
	}
	if !bytes.Equal(plain[16:], hmacSHA256(key, unhex(t, v.LocalNonce))) {
		t.Fatal("neg response HMAC field is not HMAC(localKey, localNonce)")
	}

	h, plain, err = Unpack55AA34(unhex(t, v.SessionKey), unhex(t, v.Answer))
	if err != nil {
		t.Fatal(err)
	}
	if h.Cmd != CmdIPCLan302 || string(plain) != v.AnswerBody {
		t.Fatalf("answer: cmd %d body %q", h.Cmd, plain)
	}
}

func TestUnpack55AA34RejectsATamperedFrame(t *testing.T) {
	v := loadVectors34(t)
	frame := unhex(t, v.Answer)
	frame[30] ^= 0x01
	if _, _, err := Unpack55AA34(unhex(t, v.SessionKey), frame); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered frame: err = %v, want ErrAuth", err)
	}
}

func TestSessionKey34MatchesTinytuya(t *testing.T) {
	v := loadVectors34(t)
	got, err := sessionKey(V34, []byte(v.LocalKey), unhex(t, v.LocalNonce), unhex(t, v.RemoteNonce))
	assertFrame(t, "session key", got, err, unhex(t, v.SessionKey))
}

// listen starts a one-connection-at-a-time fake camera on loopback.
func listen(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func readExactly(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

// The whole negotiation against a scripted camera, compared on the wire.
func TestDial34MatchesTinytuyaOnTheWire(t *testing.T) {
	v := loadVectors34(t)
	mismatch := make(chan string, 4)
	addr := listen(t, func(conn net.Conn) {
		for _, step := range []struct {
			name string
			want string
		}{{"neg start", v.NegStart}} {
			got, err := readExactly(conn, len(step.want)/2)
			if err != nil || hex.EncodeToString(got) != step.want {
				mismatch <- step.name
				return
			}
		}
		_, _ = conn.Write(unhex(t, v.NegResp))
		for _, step := range []struct {
			name string
			want string
		}{{"neg finish", v.NegFinish}, {"heartbeat", v.Heartbeat}} {
			got, err := readExactly(conn, len(step.want)/2)
			if err != nil || hex.EncodeToString(got) != step.want {
				mismatch <- step.name
				return
			}
		}
		mismatch <- ""
	})

	s, err := Dial(context.Background(), DialConfig{
		Addr: addr, LocalKey: v.LocalKey, Version: V34,
		Rand: bytes.NewReader(unhex(t, v.LocalNonce)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if hex.EncodeToString(s.Key) != v.SessionKey {
		t.Fatalf("session key = %x, want %s", s.Key, v.SessionKey)
	}
	if err := s.Heartbeat(); err != nil {
		t.Fatal(err)
	}
	select {
	case name := <-mismatch:
		if name != "" {
			t.Fatalf("%s on the wire differs from tinytuya", name)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake camera never saw the heartbeat")
	}
}
