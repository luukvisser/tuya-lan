package tuyalan

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// The startup sequence pauses between two messages and never after the last.
func TestSendPacedPausesOnlyBetweenMessages(t *testing.T) {
	msgs := [][]byte{{1}, {2}, {3}}
	for _, tc := range []struct {
		gap  time.Duration
		want []string
	}{
		{20 * time.Millisecond, []string{"send 1", "wait 20ms", "send 2", "wait 20ms", "send 3"}},
		{0, []string{"send 1", "send 2", "send 3"}},
	} {
		var got []string
		send := func(m []byte) error { got = append(got, "send "+string(rune('0'+m[0]))); return nil }
		wait := func(_ context.Context, d time.Duration) error { got = append(got, "wait "+d.String()); return nil }
		if err := sendPaced(context.Background(), msgs, tc.gap, send, wait); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("gap %s: %v, want %v", tc.gap, got, tc.want)
		}
	}
}

func TestSendPacedStopsOnError(t *testing.T) {
	boom := errors.New("boom")
	sent := 0
	send := func([]byte) error { sent++; return nil }
	wait := func(context.Context, time.Duration) error { return boom }
	if err := sendPaced(context.Background(), [][]byte{{1}, {2}}, time.Millisecond, send, wait); !errors.Is(err, boom) || sent != 1 {
		t.Fatalf("err %v after %d sends, want boom after 1", err, sent)
	}
	failing := func([]byte) error { return boom }
	if err := sendPaced(context.Background(), [][]byte{{1}, {2}}, 0, failing, wait); !errors.Is(err, boom) {
		t.Fatalf("err %v, want boom", err)
	}
}

func TestStartupGap(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0:                     DefaultStartupGap,
		-1:                    0,
		20 * time.Millisecond: 20 * time.Millisecond,
	} {
		if got := (&Client{StartupGap: in}).startupGap(); got != want {
			t.Errorf("StartupGap %s: %s, want %s", in, got, want)
		}
	}
}

type fakeReader struct {
	deadline time.Time
	err      error
}

func (f *fakeReader) SetReadDeadline(t time.Time) error { f.deadline = t; return nil }
func (f *fakeReader) Read([]byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	return 1, nil
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }

// The next startup message waits for the camera's answer, at most the gap.
func TestAwaitReply(t *testing.T) {
	buf := make([]byte, 16)
	r := &fakeReader{}
	start := time.Now()
	if ok, err := awaitReply(context.Background(), r, buf, 50*time.Millisecond); !ok || err != nil {
		t.Fatalf("answer: %v %v, want true nil", ok, err)
	}
	if d := r.deadline.Sub(start); d < 50*time.Millisecond || d > time.Second {
		t.Errorf("deadline %s from now, want the gap", d)
	}
	r.err = timeoutErr{}
	if ok, err := awaitReply(context.Background(), r, buf, time.Millisecond); ok || err != nil {
		t.Fatalf("no answer: %v %v, want false nil", ok, err)
	}
	r.err = errors.New("closed")
	if _, err := awaitReply(context.Background(), r, buf, time.Millisecond); err == nil {
		t.Fatal("a broken conversation must end the start")
	}
	// A start that ran out of time stops instead of sending on.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.err = timeoutErr{}
	if _, err := awaitReply(ctx, r, buf, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want context.Canceled", err)
	}
	// The start's own deadline caps the wait.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	r.err = nil
	if _, err := awaitReply(ctx, r, buf, time.Hour); err != nil || time.Until(r.deadline) > time.Second {
		t.Fatalf("deadline not capped by ctx: %v", err)
	}
}

// The router's counters reach Snapshot, so "no video" can be told apart from
// "dropped here" (2026-11-04).
func TestSnapshotCarriesTheRouterCounters(t *testing.T) {
	r := &packetRouter{conns: map[uint32]*convConn{0: {}, 7: {}}}
	r.datagrams.Add(5)
	r.foreign.Add(1)
	r.badMAC.Add(2)
	r.queueFull.Add(3)
	c := &Client{router: r}
	st := c.Snapshot()
	if st.RouterDatagrams != 5 || st.RouterForeign != 1 || st.RouterBadMAC != 2 || st.RouterQueueFull != 3 || st.Conversations != 2 {
		t.Fatalf("snapshot %+v", st)
	}
	if (&Client{}).Snapshot().Conversations != 0 {
		t.Fatal("no router, no conversations")
	}
}
