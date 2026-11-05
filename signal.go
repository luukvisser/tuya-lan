package tuyalan

// Ported from Leonard Pitzu's leonardpitzu/aventproxy (MIT). Changed here:
// ReadSignal skips a frame that fails authentication instead of ending the
// exchange, and the IV is ignored on a 3.4 session, whose frames carry none.
// The route (Path, MotoID), the exported frame builders and ParseSignalFrame
// follow Andrea Cervesato's pkg/lan in thekoma/aventproxy (MIT, 2026.11.0-rc1),
// for the cloud route (cloud.go).

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Protocol-302 message types, the same vocabulary the cloud MQTT path uses.
const (
	TypeOffer      = "offer"
	TypeAnswer     = "answer"
	TypeCandidate  = "candidate"
	TypeDisconnect = "disconnect"
)

// Values of the header's path: the route a frame took. libThingP2PSDK adds it
// after building the frame, "lan" for the 6668 session and "mqtt" for the
// cloud broker; a frame without one is read as mqtt.
const (
	PathLAN  = "lan"
	PathMQTT = "mqtt"
)

// SignalHeader is the "header" object of a 302 frame.
type SignalHeader struct {
	From          string `json:"from"`
	To            string `json:"to"`
	MotoID        string `json:"moto_id"`
	Path          string `json:"path"`
	Type          string `json:"type"`
	IsPre         int    `json:"is_pre"`
	P2PSkill      int    `json:"p2p_skill,omitempty"`
	SecurityLevel int    `json:"security_level,omitempty"`
	SessionID     string `json:"sessionid"`
	TraceID       string `json:"trace_id"`
}

// ICEServer is one entry of the token list carried in an offer or answer.
type ICEServer struct {
	URLs       any    `json:"urls,omitempty"`
	Username   string `json:"username,omitempty"`
	Credential string `json:"credential,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
}

// SignalMessage is the "msg" object of a 302 frame.
type SignalMessage struct {
	SDP        string      `json:"sdp,omitempty"`
	Candidate  string      `json:"candidate,omitempty"`
	Preconnect bool        `json:"preconnect,omitempty"`
	Token      []ICEServer `json:"token"`
	// Log and TCPToken are cloud-issued and opaque to us; the app always sends
	// them, so they are passed through verbatim rather than modelled.
	Log      json.RawMessage `json:"log,omitempty"`
	TCPToken json.RawMessage `json:"tcp_token,omitempty"`
	// StreamType is left out unless set. The cloud offer carries
	// "stream_type": 1; on the imm path of the SCD951, 0, 1 and 2 made no
	// difference.
	StreamType *int `json:"stream_type,omitempty"`
}

// SignalFrame is a complete 302 body.
type SignalFrame struct {
	Header SignalHeader  `json:"header"`
	Msg    SignalMessage `json:"msg"`
}

// Offer describes the session we want from the camera.
type Offer struct {
	UID      string
	DeviceID string
	// Path is the route the frames take: PathLAN unless the cloud carries
	// them. MotoID names the cloud relay and stays empty on the LAN.
	Path      string
	MotoID    string
	SessionID string
	TraceID   string
	IV        []byte
	AESKey    string // 16 ASCII characters, sent hex-encoded in the SDP
	ICEUfrag  string
	ICEPwd    string
	// ICEServers is what the camera calls the token. It gathers no candidates
	// at all when this is empty.
	ICEServers []ICEServer
	Log        json.RawMessage
	TCPToken   json.RawMessage
	// StreamType, when not nil, goes into the offer's msg as "stream_type".
	StreamType *int
}

// NewOffer mints the identifiers a fresh session needs.
func NewOffer(uid, deviceID, iceUfrag, icePwd string) (*Offer, error) {
	key, err := randomASCII(16)
	if err != nil {
		return nil, err
	}
	suffix, err := randomASCII(8)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	trace := strings.ToUpper(uuid.NewString())
	return &Offer{
		UID:        uid,
		DeviceID:   deviceID,
		SessionID:  fmt.Sprintf("%s%d%s", deviceID, now, suffix),
		TraceID:    fmt.Sprintf("%s_%s_%d", trace, deviceID, now*1000),
		Path:       PathLAN,
		IV:         IVFromTraceID(trace),
		AESKey:     key,
		ICEUfrag:   iceUfrag,
		ICEPwd:     icePwd,
		ICEServers: placeholderICEServers(),
	}, nil
}

// IVFromTraceID derives the GCM IV the camera expects.
//
// This is not cosmetic. A random binary IV produces a frame the camera
// acknowledges and then discards without answering; only the ASCII text of a
// UUID gets acted on.
//
// On 3.5 the offer and its candidates are sealed with this one IV under the
// session key, so GCM sees a nonce more than once. The session key is new
// for every TCP session (negotiate), which bounds what that exposes to
// frames of one session, but someone recording it on the LAN could forge
// signalling frames within it. A fresh UUID per frame would avoid it; it is
// not done because whether the camera accepts candidates under an IV other
// than the offer's has not been tested on a 3.5 camera (the SCD951 this was
// measured on speaks only 3.4, where frames carry no IV).
func IVFromTraceID(traceID string) []byte {
	flat := strings.ReplaceAll(traceID, "-", "")
	if len(flat) < gcmIVLen {
		flat += strings.Repeat("0", gcmIVLen-len(flat))
	}
	return []byte(flat[:gcmIVLen])
}

// SDP renders the offer. The camera rejects a WebRTC/DTLS description on the
// LAN path with close_reason 7, so this always describes the imm transport.
func (o *Offer) SDP() string {
	now := time.Now().Unix()
	return strings.Join([]string{
		"v=0",
		fmt.Sprintf("o=- %d 1 IN IP4 127.0.0.1", now),
		"s=-",
		"t=0 0",
		"a=group:BUNDLE imm0",
		fmt.Sprintf("a=msid-semantic: WMS %s", o.SessionID),
		"m=application 9 imm 6001",
		"c=IN IP4 0.0.0.0",
		"a=rtcp:9 IN IP4 0.0.0.0",
		fmt.Sprintf("a=ice-ufrag:%s", o.ICEUfrag),
		fmt.Sprintf("a=ice-pwd:%s", o.ICEPwd),
		"a=ice-options:trickle",
		fmt.Sprintf("a=aes-key:%s", hex.EncodeToString([]byte(o.AESKey))),
		"a=mid:imm0",
		"a=rtpmap:6001 AES/KCP 330",
		fmt.Sprintf("a=ssrc:0 cname:%s", o.UID),
		"",
	}, "\r\n")
}

func (o *Offer) header(msgType string) SignalHeader {
	return SignalHeader{
		From:          o.UID,
		To:            o.DeviceID,
		MotoID:        o.MotoID,
		Path:          o.Path,
		Type:          msgType,
		IsPre:         0,
		P2PSkill:      1635,
		SecurityLevel: 3,
		SessionID:     o.SessionID,
		TraceID:       o.TraceID,
	}
}

// placeholderICEServers exists because the camera gathers no candidates at all
// when the token list is empty: it answers, then sends an empty candidate and
// disconnects.
//
// The entry is never contacted on a LAN pairing, but it must be an IP literal.
// A hostname makes the camera resolve it before gathering anything, so with no
// DNS it produces the same empty candidate as an empty list. This is TEST-NET-1
// from RFC 5737: reserved for documentation and never routable.
func placeholderICEServers() []ICEServer {
	return []ICEServer{{URLs: "stun:192.0.2.1:3478"}}
}

// SendOffer writes the offer to the camera.
func (o *Offer) SendOffer(s *Session) error {
	return sendSignal(s, o.IV, o.OfferFrame())
}

// OfferFrame is the 302 body of the offer.
func (o *Offer) OfferFrame() SignalFrame {
	return SignalFrame{
		Header: o.header(TypeOffer),
		Msg: SignalMessage{
			SDP:        o.SDP(),
			Preconnect: true,
			StreamType: o.StreamType,
			Token:      o.ICEServers,
			Log:        o.Log,
			TCPToken:   o.TCPToken,
		},
	}
}

// SendCandidate trickles one local ICE candidate.
func (o *Offer) SendCandidate(s *Session, candidate string) error {
	return sendSignal(s, o.IV, o.CandidateFrame(candidate))
}

// CandidateFrame is one local ICE candidate as a 302 body.
func (o *Offer) CandidateFrame(candidate string) SignalFrame {
	if !strings.HasPrefix(candidate, "a=") {
		candidate = "a=" + candidate
	}
	if !strings.HasSuffix(candidate, "\r\n") {
		candidate += "\r\n"
	}
	return SignalFrame{
		Header: o.header(TypeCandidate),
		Msg:    SignalMessage{Candidate: candidate, Token: []ICEServer{}},
	}
}

// DisconnectMessage is the msg of a disconnect frame. It carries no token.
type DisconnectMessage struct {
	CloseReasonLocal int `json:"close_reason_local"`
	CloseReason      int `json:"close_reason"`
}

// DisconnectFrame is a complete 302 disconnect body.
type DisconnectFrame struct {
	Header SignalHeader      `json:"header"`
	Msg    DisconnectMessage `json:"msg"`
}

// closeReasonLocalClose is what libThingP2PSDK puts in close_reason when it
// ends a session itself, with close_reason_local reset to 0.
const closeReasonLocalClose = 4

// DisconnectFrame ends the session at the camera. The LAN route never sends
// it: closing the 6668 session is enough there.
func (o *Offer) DisconnectFrame() DisconnectFrame {
	return DisconnectFrame{
		Header: o.header(TypeDisconnect),
		Msg:    DisconnectMessage{CloseReason: closeReasonLocalClose},
	}
}

func sendSignal(s *Session, iv []byte, frame SignalFrame) error {
	body, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return s.Send(CmdIPCLan302, iv, body)
}

// ErrNoSignal means no signalling frame arrived in time. The control
// connection is still usable.
var ErrNoSignal = errors.New("tuyalan: no signalling frame")

// ReadSignal returns the next 302 frame, skipping acknowledgements and any
// status pushes that share the connection.
func ReadSignal(s *Session, timeout time.Duration) (*SignalFrame, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h, payload, err := s.Recv(time.Until(deadline))
		if errors.Is(err, ErrAuth) {
			continue
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Cmd != CmdIPCLan302 {
			continue
		}
		if frame := parseSignal(s, payload); frame != nil {
			return frame, nil
		}
	}
	return nil, fmt.Errorf("%w within %s", ErrNoSignal, timeout)
}

// parseSignal decodes a command-32 payload, or returns nil for one that is
// not a signalling frame: the 32-byte acknowledgements are not JSON.
// ErrCameraEnded is the camera ending the session with a disconnect signal:
// a normal end, not a failure of the local path.
var ErrCameraEnded = errors.New("tuyalan: camera ended the session")

// endsSession reports whether frame is a disconnect for the session ours. A
// disconnect that names another session id is not ours (foreign): ending
// ours on it cut a running local stream after ~11 s, the time the camera
// took to drop the previous, already closed session (02-11-2026). A frame
// without a session id, or ours unknown, counts as ours, as before.
func endsSession(frame *SignalFrame, ours string) (ends, foreign bool) {
	if frame == nil || frame.Header.Type != TypeDisconnect {
		return false, false
	}
	if frame.Header.SessionID != "" && ours != "" && frame.Header.SessionID != ours {
		return false, true
	}
	return true, false
}

func parseSignal(s *Session, payload []byte) *SignalFrame {
	if s.Version == V35 {
		payload = StripRetcode(payload)
	}
	var frame SignalFrame
	if err := json.Unmarshal(payload, &frame); err != nil || frame.Header.Type == "" {
		return nil
	}
	return &frame
}

// ParseSignalFrame reads the parts of a 302 frame a session acts on: the
// type, the session id and the sdp or candidate. Everything else is left out,
// so a field in a form not expected here (a ttl as a string, say) cannot cost
// the whole frame.
func ParseSignalFrame(data []byte) (SignalFrame, error) {
	var raw struct {
		Header struct {
			From      string `json:"from"`
			To        string `json:"to"`
			Type      string `json:"type"`
			SessionID string `json:"sessionid"`
		} `json:"header"`
		Msg struct {
			SDP       string `json:"sdp"`
			Candidate string `json:"candidate"`
		} `json:"msg"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return SignalFrame{}, err
	}
	return SignalFrame{
		Header: SignalHeader{From: raw.Header.From, To: raw.Header.To, Type: raw.Header.Type, SessionID: raw.Header.SessionID},
		Msg:    SignalMessage{SDP: raw.Msg.SDP, Candidate: raw.Msg.Candidate},
	}, nil
}

func randomASCII(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	for i := range out {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}
