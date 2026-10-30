// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <spdlog/spdlog.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace moq::peering {

    /**
     * @brief Role of this node in the relay network
     */
    enum class NodeType : uint8_t
    {
        kVia = 0, ///< Relay that only forwards between relays
        kEdge,    ///< Relay that also has clients
        kStub,    ///< Relay that is a stub edge
    };

    /// Cost of a node when no other metric is configured. Lower path sums are preferred.
    inline constexpr std::uint64_t kDefaultNodeMetric = 100;

    /**
     * @brief How an announcement should be interpreted
     */
    enum class Announcement : uint8_t
    {
        kTrack = 0, ///< A single track name
        kNamespace, ///< A namespace, which may cover many tracks
    };

    /**
     * @brief How an object is carried between relays
     */
    enum class DataType : uint8_t
    {
        kDatagram = 0,
        kExistingStream,
        kNewStream,
        kControlSignaling,
        kFetchNewStream,
        kFetchExistingStream,
    };

    /**
     * @brief Track identity carried by the peering protocol
     *
     * @details The namespace is an ordered list of tuple values, the same shape MoQ uses, without
     *      depending on a MoQ session. `name` is empty when the announcement is namespace-only.
     */
    struct TrackName
    {
        std::vector<std::vector<uint8_t>> name_space;
        std::vector<uint8_t> name;
    };

    /**
     * @brief Subscribe parameters exchanged with peers
     */
    struct SubscribeParams
    {
        uint8_t priority{ 0 };
        uint64_t delivery_timeout_ms{ 0 };
        uint64_t expires_ms{ 0 };
        uint8_t forward{ 1 };
        std::optional<uint64_t> new_group_request_id;
    };

    /**
     * @brief Configuration for one peering node
     *
     * @details Transport certificates are file paths, never embedded. Leave `logger` empty to have
     *      the library create one.
     */
    struct Config
    {
        std::string node_id;
        NodeType node_type{ NodeType::kEdge };

        /// Cost advertised for this node. A peering session uses its own metric when that value is greater.
        std::uint64_t node_metric{ kDefaultNodeMetric };

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

    /**
     * @brief Application callbacks
     *
     * @details Peering runs these on its own threads. The application translates them into whatever
     *      protocol it implements, such as MoQ. Every method has an empty default.
     *
     *      SetDelegate(nullptr) before destroying the delegate. Callbacks already running may still
     *      finish.
     */
    class Delegate
    {
      public:
        virtual ~Delegate() = default;

        /// A peer subscribed to this name. Subscribe locally if the application publishes it.
        virtual void OnPeerSubscribe(const TrackName& name, std::uint64_t track_hash, const SubscribeParams& params)
        {
            (void)name;
            (void)track_hash;
            (void)params;
        }

        /**
         * @brief A peered subscribe was withdrawn
         *
         * @param track_hash           Full track name hash
         * @param subscribers_remain   True when some other peer still subscribes to the track
         */
        virtual void OnPeerUnsubscribe(std::uint64_t track_hash, bool subscribers_remain)
        {
            (void)track_hash;
            (void)subscribers_remain;
        }

        /// A peer announced or withdrew a namespace.
        virtual void OnPeerNamespace(const std::vector<std::vector<uint8_t>>& name_space, bool withdrawn)
        {
            (void)name_space;
            (void)withdrawn;
        }

        /// A peer announced or withdrew a track.
        virtual void OnPeerTrack(const TrackName& name, bool withdrawn)
        {
            (void)name;
            (void)withdrawn;
        }

        /// Object bytes from a peer for a name this node subscribed to.
        virtual void OnPeerData(std::uint64_t track_hash,
                                bool is_new_stream,
                                std::optional<std::uint64_t> stream_id,
                                std::shared_ptr<const std::vector<uint8_t>> data)
        {
            (void)track_hash;
            (void)is_new_stream;
            (void)stream_id;
            (void)data;
        }

        /// The peer closed the stream that was carrying objects for a track.
        virtual void OnPeerStreamClosed(std::uint64_t track_hash, std::uint64_t stream_id, bool reset)
        {
            (void)track_hash;
            (void)stream_id;
            (void)reset;
        }

        /// An outbound or accepted peering session finished its handshake.
        virtual void OnPeerUp(std::uint64_t session_id) { (void)session_id; }

        /// A peering session disconnected.
        virtual void OnPeerDown(std::uint64_t session_id) { (void)session_id; }
    };

    /// Whether this node accepted the peer or opened the connection itself.
    enum class PeerOrigin : std::uint8_t
    {
        kAccepted = 0, ///< The peer connected to this node and the connection was accepted
        kDialed,       ///< This node opened the connection to the peer
    };

    /// Handshake state of one peering session.
    enum class PeerLinkStatus : std::uint8_t
    {
        kConnecting = 0,
        kConnected,
        kDisconnected,
    };

    /// Peering node id text. This is `NodeId::Value(uint64_t)`, `high.high:low.low`.
    std::string FormatNodeId(std::uint64_t id);

    /// One peering session, copied for readers outside the peering threads.
    struct PeerSnapshot
    {
        std::uint64_t session_id{ 0 };
        PeerOrigin origin{ PeerOrigin::kAccepted };
        PeerLinkStatus status{ PeerLinkStatus::kConnecting };
        std::string host;
        std::uint16_t port{ 0 };

        /// True after the peering handshake has supplied the remote node identity.
        bool identified{ false };
        std::uint64_t node_id{ 0 };
        std::string contact;
        NodeType node_type{ NodeType::kEdge };

        /// Smoothed RTT in microseconds. Zero when the connection has no sample yet.
        std::uint64_t srtt_us{ 0 };

        /// Metric configured for this peering session. Zero when add-peer did not set one.
        std::uint64_t metric{ 0 };

        /// Metric written into this node's advertisements on this session.
        std::uint64_t node_metric{ 0 };

        /// Unix time in microseconds when the current attempt became connected. Zero otherwise.
        std::uint64_t connect_time_us{ 0 };

        /// Tracks this relay is forwarding to the peer because of a subscribe.
        std::uint64_t subscribe_tracks{ 0 };

        /// Tracks arriving from the peer that this relay is forwarding onward.
        std::uint64_t publishes{ 0 };
    };

    /// Result of an admin add, remove, restart, or metric change for one peer address.
    struct PeerAdminResult
    {
        bool ok{ false };
        std::string host;
        std::uint16_t port{ 0 };
        /// Set when the call carried a session metric.
        std::optional<std::uint64_t> metric;
        std::string action;
        std::string message;
    };

} // namespace moq::peering
