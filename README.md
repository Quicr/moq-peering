# moq-peering

[![Ubuntu](https://img.shields.io/github/actions/workflow/status/Quicr/moq-peering/ubuntu.yml?branch=main&label=Ubuntu)](https://github.com/Quicr/moq-peering/actions/workflows/ubuntu.yml)
[![MacOS](https://img.shields.io/github/actions/workflow/status/Quicr/moq-peering/macos.yml?branch=main&label=MacOS)](https://github.com/Quicr/moq-peering/actions/workflows/macos.yml)
[![Windows](https://img.shields.io/github/actions/workflow/status/Quicr/moq-peering/windows.yml?branch=main&label=Windows)](https://github.com/Quicr/moq-peering/actions/workflows/windows.yml)

C++ library for Media Over QUIC peering. Relays use it to peer with each other over QUIC and forward track names, subscribes, and objects. The library implements the peering protocol. It does not implement Media Over QUIC (MoQ). An application such as [LAPS](https://github.com/Quicr/laps) implements MoQ and uses this library.

## Documentation

- [API](docs/api.md) — `PeerManager`, `Delegate`, and the calls an application makes
- [Examples](docs/examples.md) — `moq_peering_relay`, `moq_peering_producer`, and `moq_peering_subscriber`, and how each one uses the API
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
ctest --test-dir build --output-on-failure
```

`test/peering_integration.cc` runs relays in one process. Two edges exchange a publish, a subscribe, and a datagram in each direction. A second case puts a via between two edges. A third case attaches a stub to an edge and exchanges with a far edge through that parent. None of them open a MoQ session.

Those tests generate a short-lived self-signed P-256 certificate, check that it is currently valid and signed with SHA-256, and delete the key when the test ends. Do not embed certificate or key material in source.

From LAPS, the library is added with CPM. A checkout at `../moq-peering` is used when it is present.
Otherwise CPM fetches `quicr/moq-peering`.

## Examples

[docs/examples.md](docs/examples.md) documents each binary, its flags, and the `PeerManager` calls it makes. The short form is one edge with a producer and a subscriber:

```sh
make cert
cmake --build build --target moq_peering_relay moq_peering_producer moq_peering_subscriber
./build/examples/moq_peering_relay --cert build/server-cert.pem --key build/server-key.pem --listen 33434
./build/examples/moq_peering_producer --cert build/server-cert.pem --key build/server-key.pem --peer 127.0.0.1:33434
./build/examples/moq_peering_subscriber --cert build/server-cert.pem --key build/server-key.pem --peer 127.0.0.1:33434
```

`make cert` writes a self-signed P-256 certificate signed with SHA-256 under `build/`. The examples read those files, check validity, key strength, and signature, and accept the self-signed pair for local use. Certificate bytes stay out of source.
