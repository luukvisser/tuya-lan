package tuyalan

// Ported from Leonard Pitzu's leonardpitzu/aventproxy (MIT).

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// message builds a media message from a sub-header and a payload. The 32-byte
// header carries the command and the stream description.
func message(subHeader, payload []byte) []byte {
	msg := make([]byte, mediaHeaderLen)
	binary.LittleEndian.PutUint32(msg[:4], CmdMediaVideo)
	binary.LittleEndian.PutUint16(msg[26:28], 1280)
	binary.LittleEndian.PutUint16(msg[28:30], 720)
	msg[30] = 20
	return append(append(msg, subHeader...), payload...)
}

// longSubHeader is the form that states a length: length, timestamp, flags.
func longSubHeader(payloadLen int, ts uint64) []byte {
	sub := make([]byte, subHeaderLen)
	binary.LittleEndian.PutUint32(sub[:4], uint32(payloadLen+subHeaderOverhead))
	binary.LittleEndian.PutUint64(sub[4:12], ts)
	copy(sub[12:16], []byte{0x00, 0x00, 0x00, 0x0a})
	return sub
}

// shortSubHeader is the form without a length: a 4-byte clock, then the flags.
func shortSubHeader(ts uint32) []byte {
	sub := make([]byte, shortSubHeaderLen)
	binary.LittleEndian.PutUint32(sub[:4], ts)
	copy(sub[4:8], []byte{0x00, 0x00, 0x00, 0x0a})
	return sub
}

func TestLongFormIsRecognisedByItsLength(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 1102)
	payload[0], payload[1] = 0x3c, 0x85

	cmd, ts, long, got, ok := mediaPayload(message(longSubHeader(len(payload), 9999), payload))
	if !ok || cmd != CmdMediaVideo {
		t.Fatalf("did not parse as video: ok=%v cmd=%#x", ok, cmd)
	}
	if !long {
		t.Fatal("a sub-header whose length accounts for the payload is the long form")
	}
	if ts != 9999 {
		t.Fatalf("timestamp = %d, want 9999", ts)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %d bytes, want %d", len(got), len(payload))
	}
}

// The short form has no length, so its first four bytes are a clock that reads
// as an impossible length. Taking it at face value is what dropped four fifths
// of the video.
func TestShortFormIsNotMistakenForALength(t *testing.T) {
	payload := bytes.Repeat([]byte{0xcd}, 1102)
	payload[0], payload[1] = 0x3c, 0x01

	_, _, long, got, ok := mediaPayload(message(shortSubHeader(0x985c1025), payload))
	if !ok {
		t.Fatal("a short-form message must still parse")
	}
	if long {
		t.Fatal("read as the long form; its length field is payload data")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = % x..., want it to start 3c 01 and run %d bytes", got[:2], len(payload))
	}
}

// Bytes taken off the wire, from the sub-header to the start of the payload.
func TestCapturedSubHeaders(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sub    string
		long   bool
		leader string
	}{
		{"keyframe fragment", "5a0400008060fe46250738c00000000a", true, "3c05"},
		{"predicted fragment", "25105c980000000a", false, "3c01"},
		{"predicted slice start", "25367e500000000a", false, "3c81"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := hex.DecodeString(tc.sub)
			if err != nil {
				t.Fatal(err)
			}
			leader, err := hex.DecodeString(tc.leader)
			if err != nil {
				t.Fatal(err)
			}
			payload := append(leader, bytes.Repeat([]byte{0x5a}, 1102-len(leader))...)

			_, _, long, got, ok := mediaPayload(message(sub, payload))
			if !ok {
				t.Fatal("did not parse")
			}
			if long != tc.long {
				t.Fatalf("long form = %v, want %v", long, tc.long)
			}
			if len(got) != 1102 {
				t.Fatalf("payload = %d bytes, want 1102", len(got))
			}
			if !bytes.HasPrefix(got, leader) {
				t.Fatalf("payload starts % x, want % x", got[:2], leader)
			}
		})
	}
}

func TestTooShortToParse(t *testing.T) {
	if _, _, _, _, ok := mediaPayload(make([]byte, mediaHeaderLen+4)); ok {
		t.Fatal("a message with no room for a sub-header must not parse")
	}
}

func TestStartupSequenceClarity(t *testing.T) {
	word := func(msgs [][]byte) uint32 {
		msg := msgs[1+clarityMessage]
		return binary.LittleEndian.Uint32(msg[len(msg)-4:])
	}
	def, err := startupSequence("token", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := word(def); got != ClarityStandard {
		t.Fatalf("default clarity word = %d, want standard (2)", got)
	}
	hd, err := startupSequence("token", ClarityHD)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := startupSequence("token", ClarityStandard)
	if err != nil {
		t.Fatal(err)
	}
	if got := word(sd); got != 2 {
		t.Fatalf("standard clarity word = %d, want the app's 2", got)
	}
	if len(def) != len(hd) || len(hd) != len(sd) || len(sd) != 1+len(startupMessages) {
		t.Fatalf("lengths %d/%d/%d", len(def), len(hd), len(sd))
	}
	for i := range sd {
		if string(def[i]) != string(sd[i]) {
			t.Fatalf("message %d differs between the default and standard", i)
		}
		if i == 1+clarityMessage {
			if a, b := sd[i], hd[i]; string(a[:len(a)-4]) != string(b[:len(b)-4]) {
				t.Fatal("the clarity message differs in more than its last word")
			}
			continue
		}
		if string(sd[i]) != string(hd[i]) {
			t.Fatalf("message %d changed with the clarity", i)
		}
	}
	// The standard sequence is the app's own, byte for byte.
	for i, h := range startupMessages {
		if hex.EncodeToString(sd[1+i]) != h {
			t.Fatalf("startup message %d is not the app's template", i)
		}
	}
}

// cmdTalk is IOCtrlAudioSpeaker in libThingCameraSDK, the command the app's
// talk button sends. A session that sends it opens the camera's speaker and
// pauses a playing lullaby (thekoma/aventproxy issue #72); the app's preview
// never does. From Andrea Cervesato's pkg/lan/preview_test.go in
// thekoma/aventproxy (MIT).
const cmdTalk = 8

// The control messages are framed magic | requestId u32 | 0 u32 | cmd u16 |
// sub u16 | len u32 | payload. The login (cmd 1) and the app's StartPreview
// commands are all a session may send.
func TestStartupSequenceNeverTalks(t *testing.T) {
	for _, clarity := range []uint32{ClarityStandard, ClarityHD} {
		msgs, err := startupSequence(LoginToken("pw", "0123456789abcdef"), clarity)
		if err != nil {
			t.Fatal(err)
		}
		for i, msg := range msgs {
			if len(msg) < 16 {
				t.Fatalf("message %d too short: % x", i, msg)
			}
			if binary.LittleEndian.Uint32(msg[0:4]) != mediaMagic {
				t.Fatalf("message %d has no magic: % x", i, msg)
			}
			if i == 0 {
				continue // the login is laid out differently: magic, then cmd 1 as a u32
			}
			if cmd := binary.LittleEndian.Uint16(msg[12:14]); cmd == cmdTalk {
				t.Errorf("startup message %d is the talk command: % x", i, msg)
			}
		}
	}
}
