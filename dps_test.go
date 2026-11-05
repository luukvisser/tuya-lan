package tuyalan

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestParseDPSForms(t *testing.T) {
	cases := map[string][]byte{
		"data.dps":                 []byte(`{"protocol":4,"t":1,"data":{"dps":{"212":"a"}}}`),
		"dps":                      []byte(`{"devId":"x","dps":{"212":"a"},"t":1}`),
		"retcode first":            append([]byte{0, 0, 0, 0}, []byte(`{"dps":{"212":"a"}}`)...),
		"3.5 header":               append(append([]byte{}, versionHeader35...), []byte(`{"dps":{"212":"a"}}`)...),
		"retcode and 3.5 header":   append(append([]byte{0, 0, 0, 0}, versionHeader35...), []byte(`{"data":{"dps":{"212":"a"}}}`)...),
		"surrounding white spaces": []byte("  {\"dps\":{\"212\":\"a\"}}\n"),
	}
	for name, payload := range cases {
		dps, ok := ParseDPS(payload)
		if !ok || dps["212"] != "a" {
			t.Errorf("%s: got %v, %v", name, dps, ok)
		}
	}
	for _, bad := range [][]byte{nil, []byte("{}"), []byte("garbage"), []byte(`{"dps":{}}`)} {
		if _, ok := ParseDPS(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestControlPayloadIsTinytuyas(t *testing.T) {
	body, err := controlPayload(map[string]any{"201": "stop"}, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Protocol int   `json:"protocol"`
		T        int64 `json:"t"`
		Data     struct {
			DPS map[string]any `json:"dps"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Protocol != 5 || doc.T != 1700000000 || doc.Data.DPS["201"] != "stop" {
		t.Fatalf("payload %s", body)
	}
}

func TestValidDPS(t *testing.T) {
	if !ValidDPS(map[string]any{"201": "stop", "202": 3}) {
		t.Fatal("valid points refused")
	}
	for _, bad := range []map[string]any{nil, {}, {"x": 1}, {"0": 1}, {"1000": 1}} {
		if ValidDPS(bad) {
			t.Errorf("%v accepted", bad)
		}
	}
}

// Pushes go to OnDPS; a command's answer goes to the command waiting for it,
// and a query answer to both.
func TestHandleDataRoutesPushesAndAnswers(t *testing.T) {
	var got []map[string]any
	c := &Client{OnDPS: func(dps map[string]any, _ time.Time) { got = append(got, dps) }}
	push := []byte(`{"data":{"dps":{"212":"alarm"}}}`)
	c.handleData(CmdStatus, push, time.Now())
	if len(got) != 1 || got[0]["212"] != "alarm" {
		t.Fatalf("push not delivered: %v", got)
	}
	done := make(chan map[string]any, 1)
	c.waitCmd, c.waitDone = CmdControlNew, done
	c.handleData(CmdControlNew, []byte{}, time.Now())
	if _, ok := <-done; !ok || len(got) != 1 {
		t.Fatalf("control answer: delivered to waiter? pushes %v", got)
	}
	done = make(chan map[string]any, 1)
	c.waitCmd, c.waitDone = CmdDPQueryNew, done
	c.handleData(CmdDPQueryNew, []byte(`{"dps":{"246":"playing"}}`), time.Now())
	if answer := <-done; answer["246"] != "playing" || len(got) != 2 {
		t.Fatalf("query answer %v, pushes %v", answer, got)
	}
	c.handleData(CmdHeartbeat, push, time.Now())
	if len(got) != 2 {
		t.Fatal("a heartbeat reply reached OnDPS")
	}
}

func TestExchangeWithoutASession(t *testing.T) {
	c := &Client{}
	if err := c.SetDPS(t.Context(), map[string]any{"201": "stop"}); !errors.Is(err, ErrNoSession) {
		t.Fatalf("got %v", err)
	}
	if err := c.SetDPS(t.Context(), map[string]any{"bad": 1}); err == nil || errors.Is(err, ErrNoSession) {
		t.Fatalf("invalid points: got %v", err)
	}
}
