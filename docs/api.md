# Peering library API

`moq-peering` is a C++ library for Media Over QUIC peering. An application such as LAPS implements MoQ and calls this API to forward names, subscribes, and objects between relays. The library speaks the peering protocol over QUIC. It does not open a MoQ session.

The public headers are:

- `include/moq/peering/peer_manager.h`
- `include/moq/peering/types.h`

Everything below is in namespace `moq::peering`. The wire format is described in [relay-protocol.md](relay-protocol.md).

## Contents

- [Linking](#linking)
- [Lifetime and threads](#lifetime-and-threads)
- [Configuration](#configuration)
- [Names and hashes](#names-and-hashes)
- [Announcements](#announcements)
- [Subscribes](#subscribes)
- [Objects](#objects)
- [Delegate](#delegate)
- [Two relays, one object](#two-relays-one-object)
- [Errors](#errors)
- [Certificates and keys](#certificates-and-keys)

## Linking

The library target is `moq::peering`. It requires C++20. Public dependencies are picoquic and spdlog.

```cmake
target_link_libraries(my_relay PRIVATE moq::peering)
target_compile_features(my_relay PRIVATE cxx_std_20)
```

```cpp
#include <moq/peering/peer_manager.h>
```

A standalone build fetches picoquic, and picoquic fetches picotls. OpenSSL is the TLS backend:

```sh
cmake -S . -B build
cmake --build build
./build/examples/peer_relay /path/to/cert.pem /path/to/key.pem
```

Pass certificate and key paths on the command line or in configuration. Do not embed that material in source.

## Lifetime and threads

`PeerManager` owns the QUIC listener, outbound sessions, and forwarding tables. It is neither copyable nor movable.

```cpp
moq::peering::PeerManager peers(config);
```

Construction starts the listener and dials every peer in `Config::peers`. Destruction stops the reconnect thread, drops sessions, and shuts down the endpoint.

`SetDelegate` registers the callback target. The library does not own it.

```cpp
peers.SetDelegate(&app);
// ...
peers.SetDelegate(nullptr);
```

Call `SetDelegate(nullptr)` before the delegate is destroyed. A callback that has already started may still finish, so destroy the `PeerManager` before the delegate object. A practical order is: clear the delegate, destroy the manager, then destroy the delegate.

`PeerManager` methods are called from the application thread. `Delegate` methods run on peering threads. The bundled example calls `SendData` from `OnSubscribe`; that is the pattern for publishing an object in response to a remote subscribe. Protect any state the callback shares with other threads. Do not destroy the manager or the delegate from inside a callback.

Announcements and subscribes made before a session is up are stored and sent when that session finishes its handshake.

## Configuration

```cpp
struct Config {
    std::string node_id;
    NodeType node_type{ NodeType::kEdge };
    uint16_t listen_port{ 33434 };
    std::vector<std::pair<std::string, uint16_t>> peers;

    std::string tls_cert_filename;
    std::string tls_key_filename;

    uint32_t object_ttl_ms{ 5000 };
    uint64_t check_interval_ms{ 5000 };
    uint32_t init_queue_size{ 5000 };
    bool debug{ false };

    std::shared_ptr<spdlog::logger> logger;
};
```

| Field | Meaning |
| --- | --- |
| `node_id` | Application label for this node. It is advertised as the contact string. The numeric node id is `std::hash<std::string>{}(node_id)`. Give every node a distinct string. This string is not parsed as the `<high>:<low>` form in the protocol note. |
| `node_type` | `NodeType::kVia`, `kEdge` (default), or `kStub`. |
| `listen_port` | UDP port for inbound peering. Default `33434`. |
| `peers` | Outbound peers as `(host, port)`. An empty list means this node only accepts connections. |
| `tls_cert_filename` | Path to the certificate file presented by this node. |
| `tls_key_filename` | Path to the matching private key file. |
| `object_ttl_ms` | TTL, in milliseconds, attached when a subgroup stream is finished. `SendData` takes its own TTL. Default `5000`. |
| `check_interval_ms` | How often disconnected outbound peers are dialed again. Values below `2000` are raised to `2000`. Default `5000`. |
| `init_queue_size` | Accepted on `Config` and not read by the current library. |
| `debug` | When true, peer sessions log extra subscriber-node-set detail. |
| `logger` | spdlog logger. When empty, the library creates or reuses a color stderr logger named `moq-peering-` plus `node_id`. |

`NodeType` values:

| Enumerator | Value | Role |
| --- | --- | --- |
| `kVia` | 0 | Forwards between relays. |
| `kEdge` | 1 | Relay that also has clients. |
| `kStub` | 2 | Stub edge. |

QUIC connections use the ALPN `moq-peering`. The transport does not configure a trust anchor, so the peer certificate is not validated. Relays with different certificates can still connect. Each node still presents the certificate loaded from `tls_cert_filename`.

```cpp
moq::peering::Config config;
config.node_id = "edge-sea-1";
config.node_type = moq::peering::NodeType::kEdge;
config.listen_port = 33440;
config.peers = { { "10.1.2.3", 33434 } };
config.tls_cert_filename = "/etc/moq/cert.pem";
config.tls_key_filename = "/etc/moq/key.pem";
config.logger = spdlog::stdout_color_mt("edge-sea-1");
config.logger->set_level(spdlog::level::info);

moq::peering::PeerManager peers(config);
```

## Names and hashes

A track name has the same shape as a MoQ full track name: an ordered list of namespace tuples, then a name. Bytes are opaque. A namespace-only announcement leaves `name` empty.

```cpp
struct TrackName {
    std::vector<std::vector<uint8_t>> name_space;
    std::vector<uint8_t> name;
};
```

```cpp
moq::peering::TrackName MakeTrack(std::string_view name_space, std::string_view track)
{
    moq::peering::TrackName name;
    name.name_space.push_back({ name_space.begin(), name_space.end() });
    name.name.assign(track.begin(), track.end());
    return name;
}

const auto camera = MakeTrack("demo", "camera-1");
const auto track_hash = moq::peering::PeerManager::HashTrack(camera);
```

`HashTrack` is the full-name hash used by `SendData`, `Unsubscribe`, `HasSubscribers`, and the delegate. It is CityHash64 of the concatenated namespace tuples, CityHash64 of the name bytes, then those two values combined. An empty name hashes as CityHash64 of zero bytes. The same bytes produce the same hash as LAPS with libquicr. Call `HashTrack` rather than recomputing it.

A namespace may contain more than one tuple. Order is significant.

```cpp
moq::peering::TrackName conference;
conference.name_space.push_back({ 'r', 'o', 'o', 'm' });
conference.name_space.push_back({ 's', 't', 'a', 'g', 'e' });
conference.name = { 'v', 'i', 'd', 'e', 'o' };
```

## Announcements

```cpp
void Announce(const TrackName& name, Announcement kind, bool withdraw = false);
void Withdraw(const TrackName& name, Announcement kind);
```

`Announcement::kTrack` advertises one track. `Announcement::kNamespace` advertises a namespace that may cover many tracks. `Withdraw` is `Announce(..., true)`.

```cpp
peers.Announce(camera, moq::peering::Announcement::kTrack);

moq::peering::TrackName room;
room.name_space.push_back({ 'd', 'e', 'm', 'o' });
peers.Announce(room, moq::peering::Announcement::kNamespace);

peers.Withdraw(camera, moq::peering::Announcement::kTrack);
```

Use the same `Announcement` value on withdraw that was used on the original announce.

When this node announces, every remote subscribe whose namespace is a prefix of the announced namespace (or the other way around) is reported again through `Delegate::OnSubscribe`. Tuple hashes are compared in order. A shorter namespace matches when every tuple it has equals the other namespace.

Peers learn the announcement through `Delegate::OnTrack` or `Delegate::OnNamespace`.

## Subscribes

```cpp
struct SubscribeParams {
    uint8_t priority{ 0 };
    uint64_t delivery_timeout_ms{ 0 };
    uint64_t expires_ms{ 0 };
    uint8_t forward{ 1 };
    std::optional<uint64_t> new_group_request_id;
};

void Subscribe(const TrackName& name, const SubscribeParams& params);
void UpdateSubscribe(const TrackName& name, const SubscribeParams& params);
void Unsubscribe(std::uint64_t track_hash);
bool HasSubscribers(std::uint64_t track_hash) const;
```

| Field | Meaning |
| --- | --- |
| `priority` | Forwarded to peers and used as the QUIC priority of a new object stream. |
| `delivery_timeout_ms` | Delivery timeout in milliseconds. `0` leaves it unset. |
| `expires_ms` | Subscribe lifetime in milliseconds. `0` leaves it unset. |
| `forward` | Non-zero asks peers to forward objects. Zero pauses forwarding. Default `1`. |
| `new_group_request_id` | Set only when the subscriber is asking for a new group. |

```cpp
moq::peering::SubscribeParams params;
params.priority = 10;
params.delivery_timeout_ms = 1000;
params.forward = 1;

peers.Subscribe(camera, params);
```

`Subscribe` records interest for this node and advertises it to current peers. Later sessions receive it during handshake sync. The local delegate is not called for a subscribe this node originates. The peer that can publish the name receives `Delegate::OnSubscribe`.

Call `Subscribe` once per track. Change parameters with `UpdateSubscribe`. `UpdateSubscribe` does nothing when this node has no subscribe for that name.

```cpp
params.priority = 20;
params.new_group_request_id = 7;
peers.UpdateSubscribe(camera, params);
```

`Unsubscribe` withdraws this node's subscribe. It does nothing when this node has no subscribe for that hash.

```cpp
peers.Unsubscribe(moq::peering::PeerManager::HashTrack(camera));
```

`HasSubscribers` is true when the forwarding table still has at least one peer path for that full-name hash. A local `Subscribe` does not make it true. It becomes true on the node that is asked to publish, after a remote subscribe has been attached to a peer.

```cpp
if (peers.HasSubscribers(track_hash)) {
    // At least one peer still wants objects for this track.
}
```

## Objects

```cpp
enum class DataType : uint8_t {
    kDatagram = 0,
    kExistingStream,
    kNewStream,
    kControlSignaling,
    kFetchNewStream,
    kFetchExistingStream,
};

void SendData(std::uint64_t track_hash,
              uint8_t priority,
              uint32_t ttl_ms,
              DataType type,
              uint64_t group_id,
              uint64_t subgroup_id,
              std::shared_ptr<const std::vector<uint8_t>> data);

void EndSubgroup(std::uint64_t track_hash,
                 uint64_t group_id,
                 uint64_t subgroup_id,
                 bool reset = false);
```

`SendData` fans the object out to every peer subscribed to `track_hash`. With no subscribers the call does nothing. `data` must be non-null. The bytes are the object payload. The library adds the peering header.

`SendData` acts on three types:

| Type | Transport | Stream rule |
| --- | --- | --- |
| `kDatagram` | One unreliable datagram. | `group_id` and `subgroup_id` are not used. |
| `kNewStream` | Reliable unidirectional stream. | Opens the stream for `(group_id, subgroup_id)` when that pair has none. |
| `kExistingStream` | Bytes on the stream already opened for that pair. | Dropped until a `kNewStream` has created the stream. |

`kControlSignaling`, `kFetchNewStream`, and `kFetchExistingStream` are present on the enumeration and are not selected by `SendData`.

`priority` is the QUIC priority of a stream created by `kNewStream`. `ttl_ms` is the object time to live in milliseconds, carried on the peering header.

A subgroup is one QUIC stream. The first object on a `(group_id, subgroup_id)` pair uses `kNewStream`. Later objects on that pair use `kExistingStream`. A new group or subgroup starts another stream. `EndSubgroup` finishes that stream. `reset == false` sends FIN after bytes already queued. `reset == true` resets the stream.

Datagram:

```cpp
auto payload = std::make_shared<std::vector<uint8_t>>(
    std::vector<uint8_t>{ 'p', 'e', 'e', 'r' });

peers.SendData(track_hash,
               /*priority=*/10,
               /*ttl_ms=*/1000,
               moq::peering::DataType::kDatagram,
               /*group_id=*/0,
               /*subgroup_id=*/0,
               std::move(payload));
```

Stream, two objects, then a clean end:

```cpp
constexpr uint64_t kGroup = 1;
constexpr uint64_t kSubgroup = 0;

auto first = std::make_shared<const std::vector<uint8_t>>(std::vector<uint8_t>{ 0x01 });
auto rest = std::make_shared<const std::vector<uint8_t>>(std::vector<uint8_t>{ 0x02, 0x03 });

peers.SendData(track_hash, 10, 1000, moq::peering::DataType::kNewStream, kGroup, kSubgroup, first);
peers.SendData(track_hash, 10, 1000, moq::peering::DataType::kExistingStream, kGroup, kSubgroup, rest);
peers.EndSubgroup(track_hash, kGroup, kSubgroup, /*reset=*/false);
```

Reset a subgroup the receiver should discard:

```cpp
peers.EndSubgroup(track_hash, kGroup, kSubgroup, /*reset=*/true);
```

The subscriber receives payload bytes in `Delegate::OnData`. For a datagram, `is_new_stream` is false and `stream_id` is empty. For a stream object, `stream_id` is set and `is_new_stream` is true on the first object of that QUIC stream. `OnPeerStreamClosed` follows when the peer closes that stream. `reset` is true when the peer reset it.

## Delegate

```cpp
class Delegate {
  public:
    virtual ~Delegate() = default;

    virtual void OnSubscribe(const TrackName& name,
                             std::uint64_t track_hash,
                             const SubscribeParams& params);

    virtual void OnUnsubscribe(std::uint64_t track_hash, bool subscribers_remain);

    virtual void OnNamespace(const std::vector<std::vector<uint8_t>>& name_space, bool withdrawn);
    virtual void OnTrack(const TrackName& name, bool withdrawn);

    virtual void OnData(std::uint64_t track_hash,
                        bool is_new_stream,
                        std::optional<std::uint64_t> stream_id,
                        std::shared_ptr<const std::vector<uint8_t>> data);

    virtual void OnPeerStreamClosed(std::uint64_t track_hash,
                                    std::uint64_t stream_id,
                                    bool reset);

    virtual void OnPeerUp(std::uint64_t session_id);
    virtual void OnPeerDown(std::uint64_t session_id);
};
```

Every method has an empty default. Override the ones the application handles.

| Callback | When it runs |
| --- | --- |
| `OnSubscribe` | A peer subscribed to `name`. `track_hash` is the value to pass to `SendData` and `HasSubscribers`. Also runs when a local announce matches a subscribe already known. |
| `OnUnsubscribe` | That peered subscribe was withdrawn. `subscribers_remain` is true when some other peer still wants the track. |
| `OnNamespace` | A peer announced or withdrew a namespace. `withdrawn` is true on withdraw. |
| `OnTrack` | A peer announced or withdrew one track. |
| `OnData` | Object bytes for a name this node subscribed to. |
| `OnPeerStreamClosed` | The peer closed the stream that carried objects for `track_hash`. |
| `OnPeerUp` | An outbound or accepted session finished its handshake. `session_id` identifies that QUIC connection. |
| `OnPeerDown` | That session disconnected. Subscriptions learned only through it are withdrawn. |

`OnData` is delivered only for a full-name hash this node has subscribed to.

```cpp
class RelayApp : public moq::peering::Delegate {
  public:
    explicit RelayApp(moq::peering::PeerManager& peers)
      : peers_(peers)
    {
    }

    void OnSubscribe(const moq::peering::TrackName&,
                     std::uint64_t track_hash,
                     const moq::peering::SubscribeParams& params) override
    {
        if (!publishes(track_hash)) {
            return;
        }

        auto payload = std::make_shared<std::vector<uint8_t>>(current_object(track_hash));
        peers_.SendData(track_hash,
                        params.priority,
                        1000,
                        moq::peering::DataType::kDatagram,
                        0,
                        0,
                        std::move(payload));
    }

    void OnUnsubscribe(std::uint64_t track_hash, bool subscribers_remain) override
    {
        if (!subscribers_remain) {
            stop_publishing(track_hash);
        }
    }

    void OnData(std::uint64_t track_hash,
                bool is_new_stream,
                std::optional<std::uint64_t> stream_id,
                std::shared_ptr<const std::vector<uint8_t>> data) override
    {
        deliver_to_local_subscriber(track_hash, is_new_stream, stream_id, data);
    }

    void OnPeerUp(std::uint64_t session_id) override { note_session(session_id, true); }
    void OnPeerDown(std::uint64_t session_id) override { note_session(session_id, false); }

  private:
    moq::peering::PeerManager& peers_;

    bool publishes(std::uint64_t) const;
    std::vector<uint8_t> current_object(std::uint64_t) const;
    void stop_publishing(std::uint64_t);
    void deliver_to_local_subscriber(std::uint64_t,
                                     bool,
                                     std::optional<std::uint64_t>,
                                     const std::shared_ptr<const std::vector<uint8_t>>&);
    void note_session(std::uint64_t, bool);
};
```

`publishes`, `current_object`, and the other helpers stand for the application's own MoQ session. The peering library does not call them.

## Two relays, one object

This is the flow implemented by `examples/peer_relay.cc`. One process runs a publisher node and a subscriber node. The subscriber dials the publisher, subscribes, and the publisher answers with one datagram. No MoQ session is opened.

```cpp
moq::peering::TrackName DemoTrack()
{
    moq::peering::TrackName name;
    const std::string name_space = "demo";
    const std::string track = "object";
    name.name_space.push_back({ name_space.begin(), name_space.end() });
    name.name.assign(track.begin(), track.end());
    return name;
}

class Publisher : public moq::peering::Delegate {
  public:
    explicit Publisher(moq::peering::PeerManager& peers)
      : peers_(peers)
      , track_hash_(moq::peering::PeerManager::HashTrack(DemoTrack()))
    {
    }

    void OnSubscribe(const moq::peering::TrackName&,
                     std::uint64_t track_hash,
                     const moq::peering::SubscribeParams&) override
    {
        if (track_hash != track_hash_) {
            return;
        }

        auto payload = std::make_shared<std::vector<uint8_t>>(
            std::vector<uint8_t>{ 'p', 'e', 'e', 'r' });
        peers_.SendData(track_hash, 10, 1000, moq::peering::DataType::kDatagram, 1, 0, std::move(payload));
    }

  private:
    moq::peering::PeerManager& peers_;
    std::uint64_t track_hash_;
};

moq::peering::Config PublisherConfig(const std::string& cert, const std::string& key)
{
    moq::peering::Config config;
    config.node_id = "1:1";
    config.node_type = moq::peering::NodeType::kEdge;
    config.listen_port = 33440;
    config.tls_cert_filename = cert;
    config.tls_key_filename = key;
    return config;
}

moq::peering::Config SubscriberConfig(const std::string& cert, const std::string& key)
{
    moq::peering::Config config;
    config.node_id = "1:2";
    config.node_type = moq::peering::NodeType::kEdge;
    config.listen_port = 33441;
    config.peers = { { "127.0.0.1", 33440 } };
    config.tls_cert_filename = cert;
    config.tls_key_filename = key;
    return config;
}

void Run(const std::string& cert, const std::string& key)
{
    const auto track = DemoTrack();

    moq::peering::PeerManager publisher_node(PublisherConfig(cert, key));
    Publisher publisher(publisher_node);
    publisher_node.SetDelegate(&publisher);
    publisher_node.Announce(track, moq::peering::Announcement::kTrack);

    moq::peering::PeerManager subscriber_node(SubscriberConfig(cert, key));
    Subscriber subscriber; // implements OnData and waits for the four bytes
    subscriber_node.SetDelegate(&subscriber);

    moq::peering::SubscribeParams params;
    params.priority = 10;
    params.delivery_timeout_ms = 1000;
    params.forward = 1;
    subscriber_node.Subscribe(track, params);

    subscriber.WaitForObject();

    publisher_node.SetDelegate(nullptr);
    subscriber_node.SetDelegate(nullptr);
}
```

`node_id` values `"1:1"` and `"1:2"` are labels. They are hashed as strings. They are not decoded as a 32-bit high and low pair.

Sequence:

1. The publisher listens on UDP `33440` and announces `demo/object`.
2. The subscriber dials `127.0.0.1:33440`.
3. After the handshake, each side calls `OnPeerUp`.
4. The subscriber's subscribe is sent. The publisher's `OnSubscribe` runs and calls `SendData`.
5. The subscriber's `OnData` receives `{ 'p', 'e', 'e', 'r' }`.

Build and run the example with certificate and key files you have already checked:

```sh
cmake -S . -B build
cmake --build build --target peer_relay
./build/examples/peer_relay /path/to/cert.pem /path/to/key.pem
```

A successful run prints `received 4 bytes`.

## Errors

`PeerManager`'s constructor throws `std::runtime_error` when the QUIC context cannot be created, the network thread cannot start, or the listen port cannot be bound. A missing or unreadable certificate or key produces `Failed to create picoquic context; check the certificate and key files`. A port already in use produces `picoquic network thread failed to bind`.

An outbound host that does not resolve throws `Failed to resolve peering peer` plus the host name.

```cpp
try {
    moq::peering::PeerManager peers(config);
    peers.SetDelegate(&app);
} catch (const std::exception& ex) {
    // Construction failed. The manager was not created.
}
```

`Subscribe`, `Announce`, `SendData`, and `EndSubgroup` do not throw for "no peer" or "no subscriber". Those calls update local state or do nothing until a session and a subscribe exist.

`UpdateSubscribe` and `Unsubscribe` do nothing when this node has no matching local subscribe. `SendData` with `kExistingStream` does nothing for a `(group_id, subgroup_id)` pair that has no open stream. `EndSubgroup` does nothing when that pair has no stream.

## Certificates and keys

`tls_cert_filename` and `tls_key_filename` are filesystem paths. The library loads them into picoquic and does not accept certificate bytes in `Config`. Keep the private key out of source, logs, and this document.

Before pointing a deployment at a certificate file, inspect it:

```sh
openssl x509 -text -noout -in /path/to/cert.pem
```

Check these properties:

- Validity: `notBefore` is in the past and `notAfter` is in the future.
- Public key: RSA at least 2048 bits, or ECDSA on P-256 or a stronger curve.
- Signature: a SHA-2 algorithm. MD5 and SHA-1 signatures are not acceptable.
- Issuer: a self-signed certificate is only appropriate for development, tests, or an internal deployment where every peer is configured to expect it.

The private key file must match that certificate and must be readable only by the relay process.
