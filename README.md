# moq-peering

[![Ubuntu](https://img.shields.io/github/actions/workflow/status/Quicr/moq-peering/ubuntu.yml?branch=main&label=Ubuntu)](https://github.com/Quicr/moq-peering/actions/workflows/ubuntu.yml)
[![MacOS](https://img.shields.io/github/actions/workflow/status/Quicr/moq-peering/macos.yml?branch=main&label=MacOS)](https://github.com/Quicr/moq-peering/actions/workflows/macos.yml)
[![Windows](https://img.shields.io/github/actions/workflow/status/Quicr/moq-peering/windows.yml?branch=main&label=Windows)](https://github.com/Quicr/moq-peering/actions/workflows/windows.yml)

C++ library for Media Over QUIC peering. Relays use it to peer with each other over QUIC and forward track names, subscribes, and objects. The library implements the peering protocol. It does not implement Media Over QUIC (MoQ). An application such as [LAPS](https://github.com/Quicr/laps) implements MoQ and uses this library.

## Documentation

- [API](docs/api.md) — `PeerManager`, `Delegate`, and examples
- [Peering protocol](docs/relay-protocol.md) — relay-to-relay wire protocol for Media Over QUIC peering

## API

`moq::peering::PeerManager` is the entry point.

Methods the application calls:

- `Announce` / `Withdraw` advertise a track or a namespace
- `Subscribe` / `UpdateSubscribe` / `Unsubscribe` express interest
- `SendData` / `EndSubgroup` forward objects
- `HasSubscribers` reports whether any peer still wants a track
- `HashTrack` returns the full-name hash used by the calls above

`moq::peering::Delegate` is the callback interface. Peering invokes it when a peer subscribes, withdraws,
announces, delivers an object, or connects and disconnects. LAPS implements the delegate and translates
those events into MoQ.

## Build

Standalone. CMake fetches picoquic, and picoquic fetches picotls. OpenSSL is required for the TLS backend:

```sh
cmake -S . -B build
cmake --build build
./build/examples/peer_relay /path/to/cert.pem /path/to/key.pem
```

`peer_relay` runs two relays in one process and forwards a single datagram. It does not open a MoQ session.
Certificate and key paths are arguments. Check the certificate before using it (expiration, key size,
signature algorithm, and whether a self-signed certificate is intentional).

From LAPS, the library is added with CPM. A checkout at `../moq-peering` is used when it is present.
Otherwise CPM fetches `quicr/moq-peering`.
