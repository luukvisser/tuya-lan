package tuyalan

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
)

// Data points over the control connection. A camera that serves few LAN
// sessions can be streamed and controlled over one: read its status pushes
// (Client.OnDPS) and send commands (Session.SendCommand) on the session that
// carries the stream. The frames are the ones tinytuya uses for protocol 3.4
// and 3.5.
const (
	// CmdStatus is a push of changed data points.
	CmdStatus = 8
	// CmdControlNew sets data points (3.4 and 3.5).
	CmdControlNew = 13
	// CmdDPQueryNew asks for all data points (3.4 and 3.5); the answer comes
	// back under the same command.
	CmdDPQueryNew = 16
)

// versionHeader35 is the 3.5 counterpart of versionHeader34, which a 3.5
// camera may put in front of a pushed payload.
var versionHeader35 = append([]byte("3.5"), make([]byte, 12)...)

// ParseDPS reads the data points out of a status push or a query answer. The
// payload may start with a return code and a version header; the JSON holds
// the points either under data.dps (protocol 3.4 and later) or under dps.
func ParseDPS(payload []byte) (map[string]any, bool) {
	body := bytes.TrimSpace(payload)
	if len(body) >= 4 && body[0] != '{' && !bytes.HasPrefix(body, []byte("3.")) {
		body = body[4:]
	}
	for _, h := range [][]byte{versionHeader34, versionHeader35} {
		body = bytes.TrimPrefix(body, h)
	}
	if i := bytes.IndexByte(body, '{'); i > 0 {
		body = body[i:]
	}
	var doc struct {
		DPS  map[string]any `json:"dps"`
		Data struct {
			DPS map[string]any `json:"dps"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	if len(doc.Data.DPS) > 0 {
		return doc.Data.DPS, true
	}
	if len(doc.DPS) > 0 {
		return doc.DPS, true
	}
	return nil, false
}

// controlPayload is the body of a CmdControlNew frame setting dps.
func controlPayload(dps map[string]any, now time.Time) ([]byte, error) {
	return json.Marshal(map[string]any{
		"protocol": 5,
		"t":        now.Unix(),
		"data":     map[string]any{"dps": dps},
	})
}

// queryPayload is the body of a CmdDPQueryNew frame: empty, as tinytuya sends
// it for 3.4 and 3.5.
func queryPayload() []byte { return []byte("{}") }

// controlPayload33 is the body of a 3.3 CmdControl33 frame, as tinytuya sends
// it for a "default" 3.3 device: the device id doubles as the uid.
func controlPayload33(deviceID string, dps map[string]any, now time.Time) ([]byte, error) {
	return json.Marshal(map[string]any{
		"devId": deviceID,
		"uid":   deviceID,
		"t":     strconv.FormatInt(now.Unix(), 10),
		"dps":   dps,
	})
}

// queryPayload33 is the body of a 3.3 CmdDPQuery33 frame (tinytuya's "default"
// device type).
func queryPayload33(deviceID string, now time.Time) ([]byte, error) {
	return json.Marshal(map[string]string{
		"gwId":  deviceID,
		"devId": deviceID,
		"uid":   deviceID,
		"t":     strconv.FormatInt(now.Unix(), 10),
	})
}

// ValidDPS reports whether a set request is something to pass on: at least one
// point, every key a data point number.
func ValidDPS(dps map[string]any) bool {
	if len(dps) == 0 || len(dps) > 16 {
		return false
	}
	for k := range dps {
		if n, err := strconv.Atoi(k); err != nil || n <= 0 || n > 999 {
			return false
		}
	}
	return true
}
