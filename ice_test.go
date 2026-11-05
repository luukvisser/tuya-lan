package tuyalan

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

func udpSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	return sock
}

// answerChecks replies to every binding request on sock with a success that,
// like the camera's, carries no integrity.
func answerChecks(sock *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
		if req.Decode() != nil || req.Type.Class != stun.ClassRequest {
			continue
		}
		resp, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(req.TransactionID))
		if err == nil {
			_, _ = sock.WriteToUDP(resp.Raw, from)
		}
	}
}

// The success response is unauthenticated, so where it comes from is all
// that ties it to the camera. One from anywhere else must not complete the
// check: the fork accepted it.
func TestICEIgnoresASuccessFromAnotherAddress(t *testing.T) {
	ours := udpSocket(t)
	camera := udpSocket(t) // never answers
	rogue := udpSocket(t)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		success, _ := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(stun.NewTransactionID()))
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				_, _ = rogue.WriteToUDP(success.Raw, ours.LocalAddr().(*net.UDPAddr))
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	local := iceCreds{Ufrag: "abcd", Pwd: "0123456789abcdefghijklmn"}
	remote := iceCreds{Ufrag: "wxyz", Pwd: "nmlkjihgfedcba9876543210"}
	if _, err := iceConnect(ctx, ours, onePeer(camera.LocalAddr().(*net.UDPAddr)), local, remote); err == nil {
		t.Fatal("a STUN success from a third address completed the ICE check")
	}
}

func TestICECompletesWithTheCamera(t *testing.T) {
	ours := udpSocket(t)
	camera := udpSocket(t)
	go answerChecks(camera)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	local := iceCreds{Ufrag: "abcd", Pwd: "0123456789abcdefghijklmn"}
	remote := iceCreds{Ufrag: "wxyz", Pwd: "nmlkjihgfedcba9876543210"}
	if _, err := iceConnect(ctx, ours, onePeer(camera.LocalAddr().(*net.UDPAddr)), local, remote); err != nil {
		t.Fatalf("check against the camera failed: %v", err)
	}
}

func TestSamePeerComparesAddressAndPort(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 40000}
	for _, tc := range []struct {
		from *net.UDPAddr
		want bool
	}{
		{&net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 40000}, true},
		{&net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.7"), Port: 40000}, true},
		{&net.UDPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 40001}, false},
		{&net.UDPAddr{IP: net.IPv4(192, 0, 2, 8), Port: 40000}, false},
		{nil, false},
	} {
		if got := samePeer(tc.from, peer); got != tc.want {
			t.Errorf("samePeer(%v) = %v, want %v", tc.from, got, tc.want)
		}
	}
}

// Ported from Andrea Cervesato's pkg/lan/ice_test.go in thekoma/aventproxy
// (MIT, 2026.11.0-rc1, 52f376e and da81ff5): checks against several candidates.

// stunPeer answers each binding request it receives with reply, after delay.
// reply gets the request's transaction id; nil means stay silent.
func stunPeer(t *testing.T, delay time.Duration, reply func(tx [stun.TransactionIDSize]byte) *stun.Message) *net.UDPAddr {
	t.Helper()
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := sock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			msg := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
			if msg.Decode() != nil || msg.Type.Class != stun.ClassRequest {
				continue
			}
			resp := reply(msg.TransactionID)
			if resp == nil {
				continue
			}
			go func() {
				time.Sleep(delay)
				_, _ = sock.WriteToUDP(resp.Raw, from)
			}()
		}
	}()
	return sock.LocalAddr().(*net.UDPAddr)
}

func success(tx [stun.TransactionIDSize]byte) *stun.Message {
	m, _ := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(tx), stun.Fingerprint)
	return m
}

func rejection(tx [stun.TransactionIDSize]byte) *stun.Message {
	m, _ := stun.Build(stun.NewType(stun.MethodBinding, stun.ClassErrorResponse), stun.NewTransactionIDSetter(tx),
		stun.CodeUnauthorized, stun.Fingerprint)
	return m
}

var (
	testLocal  = iceCreds{Ufrag: "loca", Pwd: "localpasswordlocalpasswd"}
	testRemote = iceCreds{Ufrag: "mntr", Pwd: cameraPwd}
)

// The LAN case: one candidate that rejects ends the checks at once, with the
// rejection.
func TestICEOneRejectingCandidateFailsAtOnce(t *testing.T) {
	bad := stunPeer(t, 0, rejection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := iceConnect(ctx, udpSocket(t), onePeer(bad), testLocal, testRemote)
	if err == nil || !strings.Contains(err.Error(), "camera rejected the ICE check: 401") {
		t.Fatalf("err = %v, want the rejection", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("took %v: a lone rejection must end the checks at once", time.Since(start))
	}
}

// A candidate that rejects at once does not end the checks while another one
// may still answer.
func TestICERejectionLeavesTheOtherCandidates(t *testing.T) {
	bad := stunPeer(t, 0, rejection)
	good := stunPeer(t, 300*time.Millisecond, success)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, err := iceConnect(ctx, udpSocket(t), func() []*net.UDPAddr { return []*net.UDPAddr{bad, good} }, testLocal, testRemote)
	if err != nil {
		t.Fatalf("err = %v, want the good candidate", err)
	}
	if peer.String() != good.String() {
		t.Fatalf("peer = %v, want %v", peer, good)
	}
}

// When nobody answers in time, the last rejection is what is reported.
func TestICEReportsTheLastRejectionAtTheEnd(t *testing.T) {
	bad := stunPeer(t, 0, rejection)
	silent := stunPeer(t, 0, func([stun.TransactionIDSize]byte) *stun.Message { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	_, err := iceConnect(ctx, udpSocket(t), func() []*net.UDPAddr { return []*net.UDPAddr{bad, silent} }, testLocal, testRemote)
	if err == nil || !strings.Contains(err.Error(), "camera rejected the ICE check: 401") {
		t.Fatalf("err = %v, want the last rejection", err)
	}
}

// A camera that does not echo the transaction id still connects, and still
// rejects at once, because its reply comes from the candidate we checked.
func TestICEUnechoedReplyFromTheCandidateCounts(t *testing.T) {
	fresh := func([stun.TransactionIDSize]byte) [stun.TransactionIDSize]byte {
		var tx [stun.TransactionIDSize]byte
		copy(tx[:], "fresh-txid12")
		return tx
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok := stunPeer(t, 0, func(tx [stun.TransactionIDSize]byte) *stun.Message { return success(fresh(tx)) })
	peer, err := iceConnect(ctx, udpSocket(t), onePeer(ok), testLocal, testRemote)
	if err != nil || peer.String() != ok.String() {
		t.Fatalf("success without the echo: peer %v, err %v; want %v", peer, err, ok)
	}

	bad := stunPeer(t, 0, func(tx [stun.TransactionIDSize]byte) *stun.Message { return rejection(fresh(tx)) })
	start := time.Now()
	_, err = iceConnect(ctx, udpSocket(t), onePeer(bad), testLocal, testRemote)
	if err == nil || !strings.Contains(err.Error(), "camera rejected the ICE check: 401") || time.Since(start) > time.Second {
		t.Fatalf("rejection without the echo: err %v after %v; want it at once", err, time.Since(start))
	}
}
