# tuya-lan

Video and audio from a Tuya IPC camera over the local network, without the
cloud, in Go.

Many cameras sold under other brands are Tuya devices underneath. Their apps
stream through Tuya's cloud (WebRTC signalled over MQTT, or Tuya's relay), but
the cameras also offer a local path. This package speaks it:

- **The LAN session** on TCP 6668, protocol **3.4** or **3.5**, authenticated
  with the device's local key, or **3.3** at an address you configure for
  one camera (see below).
- **The local offer** (`IPC_LAN_302`, in command 32 of that session), its
  answer and candidates.
- **ICE/STUN** towards the camera and the **KCP** media channel over UDP.
- **The media channel's** login and decryption, delivered as frames: video as
  **H.264** RTP payloads (as the camera sends them: parameter sets whole,
  slices already fragmented as FU-A), audio as signed 16-bit little-endian PCM.

**Authors:** **Leonard Pitzu**, who worked the protocol out and wrote most
of the code; **Andrea Cervesato** ([thekoma](https://github.com/thekoma)),
in whose [aventproxy](https://github.com/thekoma/aventproxy) it grew and
whose `pkg/lan` brought the cloud route, ICE against several candidates and
more; and **Luuk Visser**, who made it a module and added protocol 3.4 and
3.3, 1080p and the data points. [Thanks](#thanks-to-leonard-pitzu) says
who did what.

Not affiliated with or endorsed by Tuya or Philips; the names are used only to
say what this works with.

## Thanks to Leonard Pitzu

This module exists because of Leonard Pitzu's work. In his fork
[leonardpitzu/aventproxy](https://github.com/leonardpitzu/aventproxy) (of
[thekoma/aventproxy](https://github.com/thekoma/aventproxy)) he found out,
on a Philips Avent SCD973 speaking protocol 3.5, how a Tuya camera streams
over the local network without the cloud, and wrote the Go code that does
it. Everything here builds on that. **Thank you, Leonard.**

### His work

- **The local signalling path.** The `IPC_LAN_302` offer goes in command 32
  of the LAN session and needs no cloud credential besides the local key: no
  `auth`, no `moto_id`, no RTC config.
- **The protocol 3.5 session**: the `6699` framing with AES-GCM, the session
  key negotiation, and the heartbeat that keeps an idle session open.
- **The camera's ICE dialect.** The camera always claims the controlling role,
  answers anyone else who claims it with 487, and sends success responses
  without MESSAGE-INTEGRITY, which pion throws away. His code does the
  connectivity checks itself.
- **The KCP media channel**: the start-up messages after the login, the two
  forms of the sub-header (only one of which states a length), reassembly of
  payloads the camera splits over several messages, video as H.264, and audio
  measured to be 16 kHz signed 16-bit little-endian PCM in 20 ms units.
- **The client** that ties these together, and a listener for the camera's
  discovery broadcast.
- **The write-up**: section 16 of his
  [PROTOCOL.md](https://github.com/leonardpitzu/aventproxy/blob/main/PROTOCOL.md),
  "The Local-Signaling Path", is the best description of this protocol there
  is.

Of his roughly 1,350 lines of Go (comments not counted), about 1,150 are
here unchanged, a little over half of this module's 2,100. Each file ported
from his code says so at the top.

### Added here

- **Protocol 3.4** framing, for the Philips Avent SCD951, which speaks
  nothing else. Along with it came the finding that the local offer must go
  without the version header in front of command 32; with the header the
  camera stays silent.
- **Protocol 3.3**, for a camera at an address you configure. Since 3.3
  proves no key, the session first queries the data points and goes on only
  if the answer decrypts under the local key, the "json obj data unvalid"
  answer of a 22-character device id included.
- **Version choice**: a configured or remembered version first, no fallback
  to 3.3, and `ErrWrongKey` for another device at the address.
- **720p or 1080p**: the third start message ends in 2 or 4.
- **Data points on the streaming session**: `OnDPS` for the camera's
  pushes, `SetDPS` and `QueryDPS` for commands, so one session can carry
  both the stream and the control. That matters for a camera that serves
  few LAN sessions.
- **A deadline on each step**: the handshake, the answer and candidates, and
  the ICE checks.
- **Source filtering in ICE**: the camera's responses carry no integrity, so
  every datagram from anywhere but its candidate address and port is dropped.
- **A disconnect for another session** (the camera ends a closed session
  about 25 s later) no longer ends the running one.
- **Tests**: nine test files with fake cameras for 3.3, 3.4 and 3.5. His
  fork had one, for the media channel.

### From thekoma/aventproxy

Andrea Cervesato (thekoma) ported the same code into aventproxy's bridge as
`pkg/lan` (2026.11.0-rc1) and hardened it. These parts of his are here too,
adapted to this client, each marked at the top of its file:

- **The cloud route** (`Client.Signaller`, cloud.go): the same imm session
  with its signalling carried by Tuya's broker instead of the 6668 session,
  for cameras that take no LAN offer. Untested on hardware, as upstream; every
  step that can fail names itself (`ErrNoAnswer`, `ErrICE` and the others).
- **ICE checks against several candidates**, matched by transaction id; one
  candidate that rejects no longer ends the checks while another may answer.
- **The frame builders** (`OfferFrame`, `CandidateFrame`, `DisconnectFrame`)
  and `ParseSignalFrame`, with the route (`Path`, `MotoID`) in the header.
- **`MediaIdleTimeout`**: an optional client-wide check that ends a quiet
  stream with `ErrMediaIdle`, on a monotonic clock; `OnControl` counts what
  the control conversation delivers.
- **Resync past a bad frame length**, and a start error that keeps the step
  it stopped at next to the context's end.

### Changed

- A **standalone module** (`github.com/luukvisser/tuya-lan`, package
  `tuyalan`), with no dependency on the rest of aventproxy, and "camera"
  instead of "monitor" in names and messages.
- Errors start with `tuyalan:`, and wrapped errors work with `errors.Is`.
- **Not ported**: the discovery listener. The version is configured, or
  found by trying 3.5 and 3.4.

## What it needs

From Tuya's cloud, once (both stay valid across sessions):

- the device's **local key** (in its device record), and
- the **P2P password** of its cloud RTC config,

plus the device id and the account's user id. Fetching them is not part of
this package.

## Tested hardware

Two cameras:

- A **Philips Avent SCD951** baby monitor, firmware 2.4.1, which speaks
  protocol **3.4** only (it refuses 3.5 at the key check). On it, a stream
  starts in about 1 s and runs at **1280x720, 25 fps** with
  `ClarityStandard`, the default (1920x1080 with `ClarityHD`). Comments in
  the code marked "SCD951" record what that camera did.
- A camera of the **SCD973 family**, firmware 1.1.12, which speaks protocol
  **3.3** only. The 3.3 handshake took 29 ms, it accepted the offer without
  the version header in front of command 32, and the first video came 0.96 s
  after the start, 1280x720 at 25 fps.

Protocol 3.5 is the path Leonard worked out on an SCD973; it has not been
tested here.

### Protocol 3.3

A 3.3 session has no key negotiation, so connecting proves nothing: anyone at
the address can answer. Pass `V33` only for a camera whose address you know
(a DHCP reservation); it is then the only version tried, and never a fallback
or a remembered one. Before the offer the session asks for the data points
(command 10, as tinytuya does) and goes on only on an answer that decrypts
under the local key and names no other device; otherwise `ErrWrongKey`.

Such a camera, with a 22-character device id, may answer that query with the
text `json obj data unvalid` instead of JSON (tinytuya's "device22",
localtuya's "type 0d"). The text decrypted under the local key, so it proves
the camera as well; it was found with a TCP capture, the answer coming 11 ms
after the query.

What it does not do, or what is untested:

- **WebRTC over the LAN signalling**: the SCD951 refuses an offer with
  `mode: webrtc` at once (`close_reason 7`), so local media is always the KCP
  transport.
- **HEVC** cameras: untested.
- **Talkback**: not on this path.
- **The cloud route**: untested on hardware, here as upstream.
- The camera only accepted local offers after it had reached Tuya's cloud
  once since its last boot.

## Use

```go
client := tuyalan.NewClient(deviceID, localKey, p2pPassword, uid,
	[]string{"192.168.1.20"}, tuyalan.DefaultVersions,
	func(f *tuyalan.VideoFrame) { /* f.NAL: an H.264 RTP payload */ },
	func(a *tuyalan.AudioFrame) { /* a.Samples: 16-bit PCM */ })
client.OnError = func(err error) { log.Print("session ended: ", err) }

ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := client.Start(ctx); err != nil {
	log.Fatal(err)
}
defer client.Close()
```

The complete, compiled examples are in [example_test.go](example_test.go).
`Hosts` may list several addresses, for several cameras: the handshake proves
the local key, so each client finds its own camera. `tuyalan.Debugf` receives
protocol-level tracing when set.

## Related

- [AlexxIT/go2rtc#2511](https://github.com/AlexxIT/go2rtc/pull/2511): a Tuya
  LAN source for go2rtc that does the signalling and talkback, not the KCP video.
- [roquerodrigo/tuya-ipc-p2p-sdk](https://github.com/roquerodrigo/tuya-ipc-p2p-sdk):
  Python, the P2P video through Tuya's cloud relay.
- [seydx/tuya-ipc-terminal](https://github.com/seydx/tuya-ipc-terminal): Tuya
  cameras as RTSP streams, through the cloud.

The same code is the local-video path of the aventproxy bridge
(`avent-webrtc-bridge`, its `pkg/lan`), and is maintained alongside it.

## Development

    go test -race ./...

The tests need no camera: the 3.4 framing is checked byte for byte against
vectors made with tinytuya (`testdata/`, a fake key), and the 3.3 and 3.4
sessions against fake cameras on localhost.

## Also thanks to

- **[tinytuya](https://github.com/jasonacox/tinytuya)** by Jason Cox and
  its contributors (MIT): the reference for the 3.3 and 3.4 framing; the
  test vectors in `testdata/` were made with it.
- **[localtuya](https://github.com/rospogrigio/localtuya)** and its
  contributors, whose "type 0d" handling describes the same 3.3 answer of
  a 22-character device id.

## Licence

MIT, see [LICENSE](LICENSE).
