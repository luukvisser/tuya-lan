package tuyalan

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// readFrame33 reads one whole 55AA frame from conn.
func readFrame33(t *testing.T, conn net.Conn) ([]byte, error) {
	t.Helper()
	head := make([]byte, header55AALen)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	h, err := ParseHeader(head)
	if err != nil {
		return nil, err
	}
	rest := make([]byte, h.Total-header55AALen)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

func pipeSession(t *testing.T, v Version) (*Session, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &Session{Version: v, Key: []byte(fakeKey), conn: a}, b
}

func shortAnswerTimeout(t *testing.T) {
	t.Helper()
	old := answerTimeout
	answerTimeout = 300 * time.Millisecond
	t.Cleanup(func() { answerTimeout = old })
}

// A 3.3 camera that ignores the offer without the version header and answers
// the one with it gets the second try.
func TestAwaitAnswer33RetriesWithTheHeader(t *testing.T) {
	shortAnswerTimeout(t)
	s, cam := pipeSession(t, V33)
	go func() {
		for {
			f, err := readFrame33(t, cam)
			if err != nil {
				return
			}
			if string(f[header55AALen:header55AALen+3]) != "3.3" {
				continue // silent, as an SCD951 was on 3.4 with the header
			}
			sdp := "v=0\r\na=ice-ufrag:wxyz\r\na=ice-pwd:nmlkjihgfedcba9876543210\r\na=aes-key:" +
				"30313233343536373839616263646566\r\n"
			for _, body := range []string{
				`{"header":{"type":"answer","path":"lan"},"msg":{"sdp":"` + jsonEscape(sdp) + `"}}`,
				`{"header":{"type":"candidate","path":"lan"},"msg":{"candidate":"a=candidate:2 1 UDP 2130706431 127.0.0.1 40002 typ host\r\n"}}`,
			} {
				reply, _ := pack55AA33([]byte(fakeKey), 2, CmdIPCLan302, []byte(body), false, true)
				if _, err := cam.Write(reply); err != nil {
					return
				}
			}
		}
	}()
	send := func() error { return s.SendCommand(CmdIPCLan302, []byte(`{"header":{"type":"offer"}}`)) }
	if err := send(); err != nil {
		t.Fatal(err)
	}
	resent := 0
	c := &Client{DeviceID: "dev1", session: s}
	remote, aesKey, peer, err := c.awaitAnswer(context.Background(), net.IPv4(127, 0, 0, 1), func() error {
		resent++
		return send()
	})
	if err != nil {
		t.Fatalf("awaitAnswer: %v", err)
	}
	if resent != 1 || !s.lan302Header {
		t.Fatalf("resent %d times, header now %t; want once, with the header", resent, s.lan302Header)
	}
	if remote.Ufrag != "wxyz" || string(aesKey) != "0123456789abcdef" || peer.Port != 40002 {
		t.Fatalf("answer %+v / %q / %v", remote, aesKey, peer)
	}
}

// 3.4 keeps its single try: its offer is measured.
func TestAwaitAnswer34DoesNotRetry(t *testing.T) {
	shortAnswerTimeout(t)
	s, cam := pipeSession(t, V34)
	go func() {
		for {
			if _, err := readFrame33(t, cam); err != nil {
				return
			}
		}
	}()
	resent := 0
	c := &Client{session: s}
	if _, _, _, err := c.awaitAnswer(context.Background(), net.IPv4(127, 0, 0, 1), func() error {
		resent++
		return nil
	}); err == nil {
		t.Fatal("a silent 3.4 camera answered")
	}
	if resent != 0 {
		t.Fatalf("3.4 resent the offer %d times", resent)
	}
}

func TestHandleData33(t *testing.T) {
	var got []map[string]any
	c := &Client{OnDPS: func(dps map[string]any, _ time.Time) { got = append(got, dps) }}
	done := make(chan map[string]any, 1)
	c.waitCmd, c.waitDone = CmdControl33, done
	c.handleData(CmdControl33, nil, time.Now())
	if _, ok := <-done; !ok || len(got) != 0 {
		t.Fatalf("control answer: waiter released? pushes %v", got)
	}
	done = make(chan map[string]any, 1)
	c.waitCmd, c.waitDone = CmdDPQuery33, done
	c.handleData(CmdDPQuery33, []byte(`{"devId":"dev1","dps":{"246":"playing"}}`), time.Now())
	if answer := <-done; answer["246"] != "playing" || len(got) != 1 {
		t.Fatalf("query answer %v, pushes %v", answer, got)
	}
}

// On 3.3 a set is command 7 with the version header and tinytuya's body; a
// query is command 10 without the header.
func TestSetAndQueryDPS33(t *testing.T) {
	s, cam := pipeSession(t, V33)
	c := &Client{DeviceID: "dev1", session: s, stopLife: func() {}}
	type sent struct {
		cmd    uint32
		header bool
		body   map[string]any
	}
	frames := make(chan sent, 2)
	go func() {
		for {
			f, err := readFrame33(t, cam)
			if err != nil {
				return
			}
			h, plain, err := Unpack55AA33([]byte(fakeKey), f)
			if err != nil {
				return
			}
			var body map[string]any
			_ = json.Unmarshal(plain, &body)
			frames <- sent{h.Cmd, string(f[header55AALen:header55AALen+3]) == "3.3", body}
			c.handleData(h.Cmd, []byte(`{"devId":"dev1","dps":{"201":"stop"}}`), time.Now())
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.SetDPS(ctx, map[string]any{"201": "stop"}); err != nil {
		t.Fatal(err)
	}
	got := <-frames
	dps, _ := got.body["dps"].(map[string]any)
	if got.cmd != CmdControl33 || !got.header || got.body["devId"] != "dev1" || got.body["uid"] != "dev1" || dps["201"] != "stop" {
		t.Fatalf("set went out as %+v", got)
	}
	if _, err := c.QueryDPS(ctx); err != nil {
		t.Fatal(err)
	}
	got = <-frames
	if got.cmd != CmdDPQuery33 || got.header || got.body["gwId"] != "dev1" {
		t.Fatalf("query went out as %+v", got)
	}
}

// The camera ends an earlier session about 11 s after it closed, on the new
// connection too. Arriving while the answer is awaited, that disconnect named
// the old session and failed the start as "refused".
func TestCollectAnswerIgnoresAnEarlierSessionsDisconnect(t *testing.T) {
	shortAnswerTimeout(t)
	s, cam := pipeSession(t, V33)
	go func() {
		sdp := "v=0\r\na=ice-ufrag:wxyz\r\na=ice-pwd:nmlkjihgfedcba9876543210\r\na=aes-key:" +
			"30313233343536373839616263646566\r\n"
		for _, body := range []string{
			`{"header":{"type":"disconnect","path":"lan","sessionid":"earlier"},"msg":{}}`,
			`{"header":{"type":"answer","path":"lan","sessionid":"ours"},"msg":{"sdp":"` + jsonEscape(sdp) + `"}}`,
			`{"header":{"type":"candidate","path":"lan","sessionid":"ours"},"msg":{"candidate":"a=candidate:2 1 UDP 2130706431 127.0.0.1 40002 typ host\r\n"}}`,
		} {
			reply, _ := pack55AA33([]byte(fakeKey), 2, CmdIPCLan302, []byte(body), false, true)
			if _, err := cam.Write(reply); err != nil {
				return
			}
		}
	}()
	c := &Client{DeviceID: "dev1", session: s, sessionID: "ours"}
	remote, _, _, err := c.collectAnswer(context.Background(), net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("collectAnswer: %v", err)
	}
	if remote.Ufrag != "wxyz" {
		t.Fatalf("answer %+v", remote)
	}

	// Our own session's disconnect still ends the start.
	s2, cam2 := pipeSession(t, V33)
	go func() {
		reply, _ := pack55AA33([]byte(fakeKey), 2, CmdIPCLan302, []byte(`{"header":{"type":"disconnect","path":"lan","sessionid":"ours"},"msg":{}}`), false, true)
		_, _ = cam2.Write(reply)
	}()
	c2 := &Client{DeviceID: "dev1", session: s2, sessionID: "ours"}
	if _, _, _, err := c2.collectAnswer(context.Background(), net.IPv4(127, 0, 0, 1)); err == nil {
		t.Fatal("our own session's disconnect did not end the start")
	}
}
