// Package tuyalan streams video and audio from a Tuya IPC camera over the local
// network, without the cloud: the Tuya LAN protocol (3.4 or 3.5) on TCP 6668,
// the IPC_LAN_302 offer in command 32, ICE/STUN to the camera, and the KCP
// media channel, decrypted into H.264 and audio frames.
//
// It needs the device's localKey and the P2P password of its cloud RTC
// config; both are fetched from Tuya's cloud once and stay valid. Comments
// marked "SCD951" record what a Philips Avent SCD951 (firmware 2.4.1, protocol
// 3.4) did; no other camera has been tested.
//
// Ported from Leonard Pitzu's leonardpitzu/aventproxy (MIT): he worked the
// protocol out against an SCD973. That fork speaks protocol 3.5 only; the 3.4
// framing next to it is new here, because the SCD951 speaks nothing else.
//
// Authors: Leonard Pitzu, who worked the protocol out and wrote most of this
// code; Andrea Cervesato (thekoma), whose aventproxy it grew in and whose
// pkg/lan added the cloud route, the ICE checks against several candidates and
// more; Luuk Visser, who made it a module and added protocol 3.4 and 3.3, 1080p
// and the data points.
package tuyalan

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Frame prefixes. 55AA is the classic format, which 3.4 keeps and seals with
// AES-ECB and an HMAC-SHA256 trailer; 6699 carries AES-GCM and is what a 3.5
// device speaks.
const (
	Prefix55AA = 0x000055AA
	Suffix55AA = 0x0000AA55
	Prefix6699 = 0x00006699
	Suffix6699 = 0x00009966

	header55AALen = 16
	header6699Len = 18
	suffixLen     = 4
	gcmIVLen      = 12
	gcmTagLen     = 16
	hmacLen       = sha256.Size
	retcodeLen    = 4

	// maxFrameLen guards a desynced stream. It is far above the largest frame
	// we expect (the signalling offer is ~1.6 kB) on purpose: tinytuya's much
	// tighter ceiling silently swallows that offer.
	maxFrameLen = 65535
)

// Command numbers used on the LAN channel.
const (
	CmdSessKeyNegStart  = 3
	CmdSessKeyNegResp   = 4
	CmdSessKeyNegFinish = 5
	CmdHeartbeat        = 9
	// CmdIPCLan302 carries the WebRTC-style offer/answer exchange, the same
	// protocol-302 body the app publishes over cloud MQTT.
	CmdIPCLan302 = 32
)

var (
	ErrShortFrame = errors.New("tuyalan: not enough data for a frame")
	ErrBadPrefix  = errors.New("tuyalan: unrecognised frame prefix")
	ErrBadLength  = errors.New("tuyalan: implausible frame length")
	// ErrAuth marks a frame that arrived whole but failed its HMAC or GCM tag.
	// The stream is still in sync, so a reader may skip it.
	ErrAuth = errors.New("tuyalan: frame failed authentication")
)

// Header describes a framed message without decrypting it.
type Header struct {
	Prefix uint32
	Seq    uint32
	Cmd    uint32
	Length uint32
	Total  int
}

// ParseHeader reads a frame header from the front of buf.
func ParseHeader(buf []byte) (Header, error) {
	if len(buf) < 4 {
		return Header{}, ErrShortFrame
	}
	switch binary.BigEndian.Uint32(buf[:4]) {
	case Prefix6699:
		if len(buf) < header6699Len {
			return Header{}, ErrShortFrame
		}
		h := Header{
			Prefix: Prefix6699,
			Seq:    binary.BigEndian.Uint32(buf[6:10]),
			Cmd:    binary.BigEndian.Uint32(buf[10:14]),
			Length: binary.BigEndian.Uint32(buf[14:18]),
		}
		h.Total = int(h.Length) + header6699Len + suffixLen
		if h.Length == 0 || h.Length > maxFrameLen {
			return Header{}, ErrBadLength
		}
		return h, nil
	case Prefix55AA:
		if len(buf) < header55AALen {
			return Header{}, ErrShortFrame
		}
		h := Header{
			Prefix: Prefix55AA,
			Seq:    binary.BigEndian.Uint32(buf[4:8]),
			Cmd:    binary.BigEndian.Uint32(buf[8:12]),
			Length: binary.BigEndian.Uint32(buf[12:16]),
		}
		h.Total = int(h.Length) + header55AALen
		if h.Length == 0 || h.Length > maxFrameLen {
			return Header{}, ErrBadLength
		}
		return h, nil
	default:
		return Header{}, ErrBadPrefix
	}
}

// Pack6699 builds an AES-GCM frame.
//
// The iv is not a free choice: the camera accepts a frame whose IV is random
// bytes, acknowledges it, and then silently ignores the payload. It only acts
// on frames whose IV is the ASCII text of a UUID, which is what the app sends.
// Callers should pass IVFromTraceID.
func Pack6699(key, iv []byte, seq, cmd uint32, payload []byte) ([]byte, error) {
	if len(iv) != gcmIVLen {
		return nil, fmt.Errorf("tuyalan: iv must be %d bytes, got %d", gcmIVLen, len(iv))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmIVLen)
	if err != nil {
		return nil, err
	}

	// The length field covers the iv, the ciphertext and the tag, but not the
	// suffix that follows it — ParseHeader adds that back.
	length := uint32(gcmIVLen + len(payload) + gcmTagLen)
	head := make([]byte, header6699Len)
	binary.BigEndian.PutUint32(head[0:4], Prefix6699)
	binary.BigEndian.PutUint16(head[4:6], 0)
	binary.BigEndian.PutUint32(head[6:10], seq)
	binary.BigEndian.PutUint32(head[10:14], cmd)
	binary.BigEndian.PutUint32(head[14:18], length)

	// Everything after the prefix is authenticated but not encrypted.
	sealed := gcm.Seal(nil, iv, payload, head[4:])

	out := make([]byte, 0, header6699Len+len(iv)+len(sealed)+suffixLen)
	out = append(out, head...)
	out = append(out, iv...)
	out = append(out, sealed...)
	return binary.BigEndian.AppendUint32(out, Suffix6699), nil
}

// Unpack6699 decrypts a complete 6699 frame.
func Unpack6699(key, frame []byte) (Header, []byte, error) {
	h, err := ParseHeader(frame)
	if err != nil {
		return Header{}, nil, err
	}
	if h.Prefix != Prefix6699 {
		return h, nil, ErrBadPrefix
	}
	if len(frame) < h.Total {
		return h, nil, ErrShortFrame
	}
	body := frame[header6699Len : h.Total-suffixLen]
	if len(body) < gcmIVLen+gcmTagLen {
		return h, nil, ErrShortFrame
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return h, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, gcmIVLen)
	if err != nil {
		return h, nil, err
	}
	plain, err := gcm.Open(nil, body[:gcmIVLen], body[gcmIVLen:], frame[4:header6699Len])
	if err != nil {
		return h, nil, fmt.Errorf("%w: cmd %d: %w", ErrAuth, h.Cmd, err)
	}
	return h, plain, nil
}

// Pack55AA34 builds a protocol 3.4 frame the way tinytuya does: the payload
// PKCS#7-padded and AES-128-ECB encrypted, then an HMAC-SHA256 over the header
// and ciphertext, then the suffix. The length field counts the ciphertext, the
// HMAC and the suffix.
//
// The payload goes in as given. Whether it carries the "3.4" version header is
// the caller's choice; see versionHeader.
func Pack55AA34(key []byte, seq, cmd uint32, payload []byte) ([]byte, error) {
	return pack55AA34(key, seq, cmd, payload, false)
}

// pack55AA34 also writes the frames a device sends, which carry a return code
// in clear between the header and the ciphertext; the tests need those.
func pack55AA34(key []byte, seq, cmd uint32, payload []byte, withRetcode bool) ([]byte, error) {
	enc, err := ecbEncrypt(key, payload)
	if err != nil {
		return nil, err
	}
	body := enc
	if withRetcode {
		body = append(make([]byte, retcodeLen), enc...)
	}
	out := make([]byte, header55AALen, header55AALen+len(body)+hmacLen+suffixLen)
	binary.BigEndian.PutUint32(out[0:4], Prefix55AA)
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint32(out[8:12], cmd)
	binary.BigEndian.PutUint32(out[12:16], uint32(len(body)+hmacLen+suffixLen))
	out = append(out, body...)
	out = append(out, hmacSHA256(key, out)...)
	return binary.BigEndian.AppendUint32(out, Suffix55AA), nil
}

// Unpack55AA34 checks and decrypts a complete 3.4 frame.
//
// Frames from the camera put a 4-byte return code in clear before the
// ciphertext and frames from a client do not. The ciphertext is a whole number
// of AES blocks, so the two cannot be confused: whatever is left over after the
// blocks is the return code.
func Unpack55AA34(key, frame []byte) (Header, []byte, error) {
	h, err := ParseHeader(frame)
	if err != nil {
		return Header{}, nil, err
	}
	if h.Prefix != Prefix55AA {
		return h, nil, ErrBadPrefix
	}
	if len(frame) < h.Total {
		return h, nil, ErrShortFrame
	}
	if int(h.Length) < hmacLen+suffixLen {
		return h, nil, ErrShortFrame
	}
	macAt := h.Total - suffixLen - hmacLen
	if !hmac.Equal(hmacSHA256(key, frame[:macAt]), frame[macAt:macAt+hmacLen]) {
		return h, nil, fmt.Errorf("%w: cmd %d: HMAC mismatch", ErrAuth, h.Cmd)
	}
	body := frame[header55AALen:macAt]
	switch len(body) % aes.BlockSize {
	case 0:
	case retcodeLen:
		body = body[retcodeLen:]
	default:
		return h, nil, fmt.Errorf("tuyalan: cmd %d carries %d bytes, not whole blocks", h.Cmd, len(body))
	}
	if len(body) == 0 {
		return h, nil, nil
	}
	plain, err := ecbDecrypt(key, body)
	if err != nil {
		return h, nil, err
	}
	// 3.4 devices put the version header inside the encryption on some
	// replies; it carries nothing we need.
	return h, bytes.TrimPrefix(plain, versionHeader34), nil
}

// versionHeader34 is what tinytuya puts in front of most 3.4 payloads: the
// version text and twelve zero bytes.
var versionHeader34 = append([]byte("3.4"), make([]byte, 12)...)

// noVersionHeader lists the commands sent without that header. The first set
// is tinytuya's (NO_PROTOCOL_HEADER_CMDS: DP queries, heartbeat, the session
// key negotiation, LAN_EXT_STREAM). Command 32 is added from a measurement on
// an SCD951 (firmware 2.4.1, 01-11-2026): the offer framed with the header got
// no answer at all, and the same offer without it got an answer and two
// candidates straight away.
var noVersionHeader = map[uint32]bool{
	10: true, 16: true, 18: true, CmdHeartbeat: true,
	CmdSessKeyNegStart: true, CmdSessKeyNegResp: true, CmdSessKeyNegFinish: true,
	64: true, CmdIPCLan302: true,
}

// versionHeader returns what goes in front of a 3.4 payload for cmd.
func versionHeader(cmd uint32) []byte {
	if noVersionHeader[cmd] {
		return nil
	}
	return versionHeader34
}

func ecbEncrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	out := make([]byte, len(plain)+pad)
	copy(out, plain)
	for i := len(plain); i < len(out); i++ {
		out[i] = byte(pad)
	}
	for i := 0; i < len(out); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], out[i:i+aes.BlockSize])
	}
	return out, nil
}

// ecbDecrypt reverses ecbEncrypt. Like tinytuya it strips padding without
// insisting on it: the HMAC has already vouched for the bytes.
func ecbDecrypt(key, data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("tuyalan: ciphertext is not a whole number of blocks")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	if n := int(out[len(out)-1]); n >= 1 && n <= aes.BlockSize {
		out = out[:len(out)-n]
	}
	return out, nil
}

// StripRetcode removes the 4-byte return code that 6699 frames from the
// camera carry inside the encryption and frames from the client do not.
// Getting this wrong shifts the session-key nonce and yields a key that
// decrypts nothing.
func StripRetcode(payload []byte) []byte {
	if len(payload) >= 4 && !bytes.HasPrefix(payload, []byte("{")) {
		return payload[4:]
	}
	return payload
}
