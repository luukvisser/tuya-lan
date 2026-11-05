# Changelog

## 0.1.0 (unreleased)

First release, split off from the aventproxy bridge's `pkg/lan`.
Authors: Leonard Pitzu, Andrea Cervesato (thekoma) and Luuk Visser.
Built on Leonard Pitzu's protocol work in leonardpitzu/aventproxy; the
README's "Thanks" section lists what he did and what this release adds.

- The Tuya LAN session on TCP 6668, protocol 3.4 and 3.5, with the version
  chosen per camera and a list of candidate addresses; protocol 3.3 for a
  camera at a configured address, proved by its first readable answer
  (JSON, or "json obj data unvalid", under its local key).
- Data points on the same session: status pushes (`OnDPS`), queries and
  commands (`SendCommand`).
- The IPC_LAN_302 offer, its answer and candidates; ICE/STUN to the camera;
  the KCP media channel.
- Video as H.264 RTP payloads (720p by default, 1080p with `ClarityHD`),
  audio as 16-bit PCM.
- `Client.Start` under the caller's context, with a deadline on every step;
  `OnError` when a running session ends; `Snapshot` for the media counters.
- The startup sequence sends each message as soon as the camera has answered
  the previous one, waiting at most `Client.StartupGap` (`DefaultStartupGap`,
  the 120 ms the original slept after every message; negative sends them back
  to back), with no pause after the last one. A disconnect left over from an
  earlier session is ignored while waiting for an answer, and a quiet media
  channel is read on rather than ended.
- From thekoma/aventproxy's `pkg/lan` (2026.11.0-rc1): the cloud route
  (`Client.Signaller`, with `MotoID` and `ICEServers`) and its step errors;
  ICE checks against several candidates; `OfferFrame`, `CandidateFrame`,
  `DisconnectFrame` and `ParseSignalFrame`; the optional `MediaIdleTimeout`
  with `ErrMediaIdle`; `OnControl`; resync past a bad frame length; a start
  error that keeps the step it stopped at.
- `Stats` counts the startup answers and the longest wait, and what the packet
  router received and dropped before KCP (datagrams, foreign senders, bad
  MACs, a full queue), to tell a camera that sent nothing from media lost on
  the way.
