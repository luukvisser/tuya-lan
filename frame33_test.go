package tuyalan

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"testing"
	"time"
)

// Frames from tinytuya 1.20 with the fake key (scratch script, 02-11-2026):
// client frames built as XenonDevice._encode_message does for 3.3, device
// frames with the return code its unpack_message strips. tinytuya decoded the
// device frames back to the same JSON.
var vectors33 = map[string]struct {
	frame, plain string
}{
	"client7Header":        {"000055aa000000010000000700000067332e33000000000000000000000000a7dee072ab048260bc41501a9ddb2fb1bb7669138172bcadf0a892d183325f4575ba0f1ff04ef63cb915f0f8c0045c3120fb03acfb092de63b6746515ff2e43859f9253a9c2fbd9d955fae1c9ed76d509d95b14e0000aa55", `{"devId":"dev1","uid":"dev1","t":"1700000000","dps":{"201":"stop"}}`},
	"client10NoHeader":     {"000055aa000000020000000a0000004841d0eb0492d38b6842a3b78a46ae4ede7bf219b841f9c5eb4eb8d99a3ba6c1378e29b566edb37047ff2ac69f9dd98c7c9e69c109d83f529f9184a7c5a030135ac98aac040000aa55", `{"gwId":"dev1","devId":"dev1","uid":"dev1","t":"1700000000"}`},
	"device10Retcode":      {"000055aa000000030000000a0000004c00000000a7dee072ab048260bc41501a9ddb2fb1b4fad5d4d5dadb27d26e3c5a345ab0f7871336e64a450af603f63b0b7850c1a7e8dcd3be96d1eccc12477bb7978ab740bc42615d0000aa55", `{"devId":"dev1","dps":{"1":true,"246":"playing"}}`},
	"device8RetcodeHeader": {"000055aa00000004000000080000005b00000000332e33000000000000000000000000a7dee072ab048260bc41501a9ddb2fb13e2e9d9bfbd1b18a8d4fa45d7ab642d1270adaeccdd2af2d0d814270735b9b800e3063d70a4bd4e649f0fa1a8c5928d856d89bc40000aa55", `{"devId":"dev1","dps":{"246":"stopping"},"t":1700000001}`},
}

func vector33(t *testing.T, name string) ([]byte, string) {
	t.Helper()
	v := vectors33[name]
	raw, err := hex.DecodeString(v.frame)
	if err != nil {
		t.Fatal(err)
	}
	return raw, v.plain
}

func TestPack55AA33MatchesTinytuya(t *testing.T) {
	for name, seqCmd := range map[string][2]uint32{"client7Header": {1, 7}, "client10NoHeader": {2, 10}} {
		want, plain := vector33(t, name)
		cmd := seqCmd[1]
		got, err := Pack55AA33([]byte(fakeKey), seqCmd[0], cmd, []byte(plain), !noVersionHeader33[cmd])
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("%s: got\n%x\nwant\n%x", name, got, want)
		}
	}
}

func TestUnpack55AA33ReadsTinytuyaFrames(t *testing.T) {
	for name := range vectors33 {
		frame, plain := vector33(t, name)
		h, got, err := Unpack55AA33([]byte(fakeKey), frame)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != plain {
			t.Errorf("%s (cmd %d): got %q, want %q", name, h.Cmd, got, plain)
		}
	}
}

func TestUnpack55AA33RefusesADamagedFrame(t *testing.T) {
	frame, _ := vector33(t, "device10Retcode")
	frame[20] ^= 0xFF
	if _, _, err := Unpack55AA33([]byte(fakeKey), frame); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want a CRC mismatch (ErrAuth)", err)
	}
}

func TestUnpack55AA33WithAnotherKeyIsNoJSON(t *testing.T) {
	frame, _ := vector33(t, "device10Retcode")
	_, got, err := Unpack55AA33([]byte("another-key-1234"), frame)
	if err != nil {
		return // refused outright is fine too
	}
	var doc map[string]any
	if json.Unmarshal(got, &doc) == nil {
		t.Fatalf("another key decrypted to JSON: %q", got)
	}
}

// fake33 is a 3.3 camera on a local port: it reads one client frame and
// answers it with the frames reply returns.
func fake33(t *testing.T, reply func(cmd uint32, plain []byte) [][]byte) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		head := make([]byte, header55AALen)
		if _, err := io.ReadFull(conn, head); err != nil {
			return
		}
		h, err := ParseHeader(head)
		if err != nil {
			return
		}
		rest := make([]byte, h.Total-header55AALen)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return
		}
		_, plain, err := Unpack55AA33([]byte(fakeKey), append(head, rest...))
		if err != nil {
			return
		}
		for _, f := range reply(h.Cmd, plain) {
			if _, err := conn.Write(f); err != nil {
				return
			}
		}
		time.Sleep(time.Second)
	}()
	return ln.Addr().String()
}

func device33(t *testing.T, key string, cmd uint32, plain string) []byte {
	t.Helper()
	f, err := pack55AA33([]byte(key), 1, cmd, []byte(plain), false, true)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func dial33(addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := Dial(ctx, DialConfig{Addr: addr, LocalKey: fakeKey, Version: V33, DeviceID: "dev1", HandshakeTimeout: 2 * time.Second})
	if err == nil {
		s.Close()
	}
	return err
}

func TestDial33ProvesTheCamera(t *testing.T) {
	var asked uint32
	addr := fake33(t, func(cmd uint32, plain []byte) [][]byte {
		asked = cmd
		var q map[string]string
		if json.Unmarshal(plain, &q) != nil || q["devId"] != "dev1" || q["gwId"] != "dev1" {
			return nil
		}
		return [][]byte{device33(t, fakeKey, CmdDPQuery33, `{"devId":"dev1","dps":{"1":true}}`)}
	})
	if err := dial33(addr); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if asked != CmdDPQuery33 {
		t.Fatalf("the identity check sent command %d, want %d", asked, CmdDPQuery33)
	}
}

func TestDial33AcceptsDataUnvalid(t *testing.T) {
	// A device22 camera answers command 10 with this text, under its own key.
	addr := fake33(t, func(uint32, []byte) [][]byte {
		return [][]byte{device33(t, fakeKey, CmdDPQuery33, `json obj data unvalid`)}
	})
	if err := dial33(addr); err != nil {
		t.Fatalf("Dial: %v", err)
	}
}

func TestDial33DataUnvalidUnderAnotherKeyIsNoProof(t *testing.T) {
	addr := fake33(t, func(uint32, []byte) [][]byte {
		return [][]byte{
			device33(t, "another-key-1234", CmdDPQuery33, `json obj data unvalid`),
			device33(t, "another-key-1234", CmdDPQuery33, `json obj data unvalid`),
		}
	})
	if err := dial33(addr); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestDial33SkipsAnAcknowledgement(t *testing.T) {
	addr := fake33(t, func(uint32, []byte) [][]byte {
		// An acknowledgement on the wire is the return code alone.
		ack := rawFrame33(1, CmdDPQuery33, make([]byte, retcodeLen))
		return [][]byte{ack, device33(t, fakeKey, CmdDPQuery33, `{"devId":"dev1","dps":{}}`)}
	})
	if err := dial33(addr); err != nil {
		t.Fatalf("Dial: %v", err)
	}
}

func TestDial33RefusesAnotherKey(t *testing.T) {
	addr := fake33(t, func(uint32, []byte) [][]byte {
		return [][]byte{
			device33(t, "another-key-1234", CmdDPQuery33, `{"devId":"dev2","dps":{}}`),
			device33(t, "another-key-1234", CmdStatus, `{"devId":"dev2","dps":{}}`),
		}
	})
	if err := dial33(addr); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestDial33RefusesAnotherDevice(t *testing.T) {
	addr := fake33(t, func(uint32, []byte) [][]byte {
		return [][]byte{device33(t, fakeKey, CmdDPQuery33, `{"devId":"dev2","dps":{}}`)}
	})
	if err := dial33(addr); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("got %v, want ErrWrongKey", err)
	}
}

func TestDial33WithoutAnswerFails(t *testing.T) {
	addr := fake33(t, func(uint32, []byte) [][]byte { return nil })
	if err := dial33(addr); err == nil {
		t.Fatal("a camera that never answers was accepted")
	}
}

// rawFrame33 is a 3.3 frame around body as it is, with length and CRC.
func rawFrame33(seq, cmd uint32, body []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, Prefix55AA)
	out = binary.BigEndian.AppendUint32(out, seq)
	out = binary.BigEndian.AppendUint32(out, cmd)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+crcLen+suffixLen))
	out = append(out, body...)
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	return binary.BigEndian.AppendUint32(out, Suffix55AA)
}

func TestSession33SendsCommand32WithOrWithoutHeader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := &Session{Version: V33, Key: []byte(fakeKey), conn: a}
	read := func() []byte {
		head := make([]byte, header55AALen)
		if _, err := io.ReadFull(b, head); err != nil {
			t.Fatal(err)
		}
		h, _ := ParseHeader(head)
		rest := make([]byte, h.Total-header55AALen)
		if _, err := io.ReadFull(b, rest); err != nil {
			t.Fatal(err)
		}
		return append(head, rest...)
	}
	for _, header := range []bool{false, true} {
		s.SetLan302Header(header)
		go func() { _ = s.SendCommand(CmdIPCLan302, []byte(`{"header":{}}`)) }()
		f := read()
		hasHeader := string(f[header55AALen:header55AALen+3]) == "3.3"
		if hasHeader != header {
			t.Fatalf("header %t: frame carries it: %t", header, hasHeader)
		}
		if _, plain, err := Unpack55AA33([]byte(fakeKey), f); err != nil || string(plain) != `{"header":{}}` {
			t.Fatalf("header %t: %q, %v", header, plain, err)
		}
	}
}
