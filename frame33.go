package tuyalan

// Protocol 3.3 framing, new here (02-11-2026): an SCD973-family unit on
// firmware 1.1.12 speaks nothing newer. Leonard Pitzu's leonardpitzu/aventproxy
// fork, which this package was ported from, speaks 3.5 only.
//
// A 3.3 frame is the classic 55AA frame with a CRC32 trailer instead of 3.4's
// HMAC: prefix, sequence number, command, length, then the payload, the CRC32
// of everything before it, and the suffix. The payload is AES-128-ECB under
// the device's local key, with no session key: 3.3 has no negotiation, so a
// handshake proves nothing about the key (see Dial). Most commands put the
// version header "3.3" and twelve zero bytes in front of the ciphertext, in
// clear (tinytuya 1.20, XenonDevice._encode_message; 3.4 puts it inside the
// encryption). Frames from the device also carry a 4-byte return code in
// clear before that.

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const crcLen = 4

// Command numbers 3.3 uses where 3.4 and 3.5 use 13 and 16 (dps.go).
const (
	// CmdControl33 sets data points; the answer comes back under the same
	// command, the new values follow as a CmdStatus push.
	CmdControl33 = 7
	// CmdDPQuery33 asks for all data points; the answer comes back under the
	// same command.
	CmdDPQuery33 = 10
)

// versionHeader33 is the clear header in front of most 3.3 ciphertexts.
var versionHeader33 = append([]byte("3.3"), make([]byte, 12)...)

// noVersionHeader33 is tinytuya's NO_PROTOCOL_HEADER_CMDS: DP queries, the
// heartbeat, the session key negotiation (unused on 3.3) and LAN_EXT_STREAM.
// Command 32 is not in it: whether the offer wants the header on 3.3 is
// unmeasured, so the session decides per attempt (Session.Lan302Header).
var noVersionHeader33 = map[uint32]bool{
	10: true, 16: true, 18: true, CmdHeartbeat: true,
	CmdSessKeyNegStart: true, CmdSessKeyNegResp: true, CmdSessKeyNegFinish: true,
	64: true,
}

// Pack55AA33 builds a 3.3 frame: payload encrypted under key, with the clear
// version header in front when header is true.
func Pack55AA33(key []byte, seq, cmd uint32, payload []byte, header bool) ([]byte, error) {
	return pack55AA33(key, seq, cmd, payload, header, false)
}

// pack55AA33 also writes the frames a device sends, which carry a return code
// in clear before the payload; the tests need those.
func pack55AA33(key []byte, seq, cmd uint32, payload []byte, header, withRetcode bool) ([]byte, error) {
	enc, err := ecbEncrypt(key, payload)
	if err != nil {
		return nil, err
	}
	var body []byte
	if withRetcode {
		body = append(body, make([]byte, retcodeLen)...)
	}
	if header {
		body = append(body, versionHeader33...)
	}
	body = append(body, enc...)
	out := make([]byte, header55AALen, header55AALen+len(body)+crcLen+suffixLen)
	binary.BigEndian.PutUint32(out[0:4], Prefix55AA)
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint32(out[8:12], cmd)
	binary.BigEndian.PutUint32(out[12:16], uint32(len(body)+crcLen+suffixLen))
	out = append(out, body...)
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	return binary.BigEndian.AppendUint32(out, Suffix55AA), nil
}

// Unpack55AA33 checks the CRC of a complete 3.3 frame and decrypts it.
//
// The CRC only guards against a damaged frame: anyone can compute it, so it
// says nothing about who sent the frame. Only a payload that decrypts under
// the camera's key into what the camera would send says that (Dial checks).
//
// What sits before the ciphertext is told apart by length, as the ciphertext
// is whole AES blocks: nothing, a return code (4), the version header (15) or
// both (19, so 3 past a block).
func Unpack55AA33(key, frame []byte) (Header, []byte, error) {
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
	if int(h.Length) < crcLen+suffixLen {
		return h, nil, ErrShortFrame
	}
	crcAt := h.Total - suffixLen - crcLen
	if crc32.ChecksumIEEE(frame[:crcAt]) != binary.BigEndian.Uint32(frame[crcAt:crcAt+crcLen]) {
		return h, nil, fmt.Errorf("%w: cmd %d: CRC mismatch", ErrAuth, h.Cmd)
	}
	body := frame[header55AALen:crcAt]
	switch len(body) % aes.BlockSize {
	case 0:
	case retcodeLen:
		body = body[retcodeLen:]
	case len(versionHeader33) % aes.BlockSize:
		if !bytes.HasPrefix(body, versionHeader33[:3]) {
			return h, nil, fmt.Errorf("tuyalan: cmd %d: 15 bytes before the ciphertext but no version header", h.Cmd)
		}
		body = body[len(versionHeader33):]
	case (retcodeLen + len(versionHeader33)) % aes.BlockSize:
		if !bytes.HasPrefix(body[retcodeLen:], versionHeader33[:3]) {
			return h, nil, fmt.Errorf("tuyalan: cmd %d: 19 bytes before the ciphertext but no version header", h.Cmd)
		}
		body = body[retcodeLen+len(versionHeader33):]
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
	return h, plain, nil
}
