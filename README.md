# moq-peering

Relay-to-relay peering. The library implements the peering protocol over QUIC and does not implement MoQ.
An application such as LAPS implements MoQ and uses this library to forward names, subscribes, and objects
between relays.

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
