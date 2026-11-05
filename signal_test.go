package tuyalan

import (
	"encoding/json"
	"testing"
)

func offerMsg(t *testing.T, streamType *int) map[string]any {
	t.Helper()
	offer, err := NewOffer("fake-uid", "fake-device", "ufrag", "pwd")
	if err != nil {
		t.Fatal(err)
	}
	offer.StreamType = streamType
	body, err := json.Marshal(offer.OfferFrame())
	if err != nil {
		t.Fatal(err)
	}
	var frame struct {
		Msg map[string]any `json:"msg"`
	}
	if err := json.Unmarshal(body, &frame); err != nil {
		t.Fatal(err)
	}
	return frame.Msg
}

func TestOfferWithoutStreamTypeIsUnchanged(t *testing.T) {
	msg := offerMsg(t, nil)
	if _, ok := msg["stream_type"]; ok {
		t.Fatalf("stream_type sent without being set: %v", msg)
	}
	if msg["preconnect"] != true || msg["sdp"] == "" {
		t.Fatalf("offer msg = %v", msg)
	}
}

func TestOfferCarriesStreamType(t *testing.T) {
	for _, n := range []int{0, 1, 2} {
		msg := offerMsg(t, &n)
		if got, ok := msg["stream_type"].(float64); !ok || int(got) != n {
			t.Fatalf("stream_type = %v, want %d", msg["stream_type"], n)
		}
	}
}

// A disconnect for another session (the camera dropping an earlier, closed
// one) must not end ours; one for ours, or without an id, does.
func TestEndsSession(t *testing.T) {
	frame := func(typ, id string) *SignalFrame {
		return &SignalFrame{Header: SignalHeader{Type: typ, SessionID: id}}
	}
	for _, tc := range []struct {
		name          string
		frame         *SignalFrame
		ours          string
		ends, foreign bool
	}{
		{"ours", frame(TypeDisconnect, "s1"), "s1", true, false},
		{"another session", frame(TypeDisconnect, "s0"), "s1", false, true},
		{"no id in the frame", frame(TypeDisconnect, ""), "s1", true, false},
		{"ours unknown", frame(TypeDisconnect, "s0"), "", true, false},
		{"not a disconnect", frame(TypeCandidate, "s0"), "s1", false, false},
		{"no frame", nil, "s1", false, false},
	} {
		ends, foreign := endsSession(tc.frame, tc.ours)
		if ends != tc.ends || foreign != tc.foreign {
			t.Errorf("%s: ends=%v foreign=%v, want %v %v", tc.name, ends, foreign, tc.ends, tc.foreign)
		}
	}
}

// The cloud route names itself in the header; the LAN route stays "lan"
// without a relay.
func TestOfferHeaderCarriesTheRoute(t *testing.T) {
	offer, err := NewOffer("uid", "dev", "abcd", "abcdefghijklmnopqrstuvwx")
	if err != nil {
		t.Fatal(err)
	}
	if h := offer.OfferFrame().Header; h.Path != PathLAN || h.MotoID != "" {
		t.Fatalf("LAN header = %+v", h)
	}
	offer.Path, offer.MotoID = PathMQTT, "moto-1"
	for _, h := range []SignalHeader{offer.OfferFrame().Header, offer.CandidateFrame("candidate:1 1 UDP 1 10.0.0.1 1 typ host").Header, offer.DisconnectFrame().Header} {
		if h.Path != PathMQTT || h.MotoID != "moto-1" || h.SessionID != offer.SessionID {
			t.Fatalf("cloud header = %+v", h)
		}
	}
	if d := offer.DisconnectFrame(); d.Header.Type != TypeDisconnect || d.Msg.CloseReason != closeReasonLocalClose {
		t.Fatalf("disconnect = %+v", d)
	}
}

// ParseSignalFrame keeps what a session acts on and survives fields in an
// unexpected form.
func TestParseSignalFrame(t *testing.T) {
	f, err := ParseSignalFrame([]byte(`{"header":{"type":"answer","sessionid":"s1","from":"dev"},"msg":{"sdp":"v=0","token":[{"ttl":"600"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Header.Type != TypeAnswer || f.Header.SessionID != "s1" || f.Msg.SDP != "v=0" {
		t.Fatalf("frame = %+v", f)
	}
}
