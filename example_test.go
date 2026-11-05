package tuyalan_test

import (
	"context"
	"fmt"
	"time"

	tuyalan "github.com/luukvisser/tuya-lan"
)

// A camera on the local network, streaming without the cloud. The device id,
// local key, P2P password and user id come from Tuya's cloud once (the local
// key from the device record, the password from its RTC config); the values
// here are fake. Without an "Output:" comment this example is compiled but
// not run.
func Example() {
	client := tuyalan.NewClient(
		"fakedevice0000000000", // device id
		"fake-local-key!!",     // localKey, 16 characters
		"fake-p2p-password",    // P2P password from the RTC config
		"fake-uid",             // the account's user id
		[]string{"192.168.1.20"},
		tuyalan.DefaultVersions, // try 3.5, then 3.4
		func(f *tuyalan.VideoFrame) {
			// f.NAL is an H.264 RTP payload; hand it to an RTP packetiser or decoder.
			fmt.Println("video", f.Width, f.Height, len(f.NAL))
		},
		func(a *tuyalan.AudioFrame) {
			// a.Samples is signed 16-bit little-endian PCM.
			fmt.Println("audio", a.SampleRate, len(a.Samples))
		},
	)
	client.OnError = func(err error) { fmt.Println("session ended:", err) }

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		fmt.Println("no local stream:", err)
		return
	}
	defer client.Close()
	fmt.Println("streaming from", client.Host, "over protocol", client.Version)
	time.Sleep(10 * time.Second)
	fmt.Printf("%+v\n", client.Snapshot())
}

// The lower layer on its own: an authenticated LAN session on TCP 6668, for
// example to check a local key without starting a stream.
func ExampleDial() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := tuyalan.Dial(ctx, tuyalan.DialConfig{
		Addr:     "192.168.1.20",
		LocalKey: "fake-local-key!!",
		Version:  tuyalan.V34,
	})
	if err != nil {
		fmt.Println("handshake failed:", err)
		return
	}
	defer s.Close()
	fmt.Println("the local key is right")
}

// A camera that speaks only protocol 3.3, at an address reserved for it. 3.3
// has no key negotiation, so it is never tried unless asked for, and then
// alone; the session proves the camera by its first readable answer.
func ExampleNewClient_protocol33() {
	client := tuyalan.NewClient(
		"fakedevice000000000000", // a 22-character device id
		"fake-local-key!!",
		"fake-p2p-password",
		"fake-uid",
		[]string{"192.168.1.21"}, // this camera's reserved address only
		[]tuyalan.Version{tuyalan.V33},
		func(f *tuyalan.VideoFrame) { fmt.Println("video", len(f.NAL)) },
		func(a *tuyalan.AudioFrame) {},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		fmt.Println("no local stream:", err)
		return
	}
	defer client.Close()
}
