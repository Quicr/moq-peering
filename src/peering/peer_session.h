// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <map>
#include <optional>
#include <set>

#include <moq/peering/types.h>
#include "messages/announce_info.h"
#include "messages/data_header.h"
#include "messages/node_info.h"
#include "messages/subscribe_info.h"
#include "messages/subscribe_node_set.h"
#include "quic_transport.h"

namespace moq::peering {

    class Engine;

    /**
     * @brief One relay-to-relay session
     */
    class PeerSession : public std::enable_shared_from_this<PeerSession>
    {
      public:
        static constexpr std::size_t kControlMessageBufferSize = 4096;

        enum class StatusValue : uint8_t
        {
            kConnecting = 0,
            kConnected,
            kDisconnected
        };

        PeerSession& operator=(const PeerSession&) { return *this; }

        PeerSession() = delete;

        PeerSession(bool is_inbound,
                    const Config& cfg,
                    const NodeInfo& node_info,
                    std::string host,
                    uint16_t port,
                    Engine& manager);

        ~PeerSession();

        /// Dial the peer. Inbound sessions are already accepted.
        void Connect();

        /// Start the handshake after the session is stored by its id.
        void Begin();

        StatusValue Status();

        /// Inbound only. The connection was accepted by the server endpoint.
        void SetConnection(std::shared_ptr<QuicConnection> connection);

        /// Install callbacks. Called after the session is owned by the engine map.
        void Attach(const std::shared_ptr<QuicConnection>& connection);

        PeerSessionId GetSessionId() const { return connection_ ? connection_->Id() : 0; }

        std::shared_ptr<QuicStream> CreateStream(uint8_t priority) const;

        void CloseStream(const std::shared_ptr<QuicStream>& stream, StreamClose flag);

        void FinishStream(const std::shared_ptr<QuicStream>& stream);
        void SendNodeInfo(const NodeInfo& node_info, bool withdraw = false) const;
        void SendSubscribeInfo(SubscribeInfo& subscribe_info, bool withdraw = false) const;
        void SendAnnounceInfo(const AnnounceInfo& announce_info, bool withdraw = false);
        void SendSns(const SubscribeNodeSet& sns, bool withdraw = false) const;

        void SendData(uint8_t priority,
                      uint32_t ttl,
                      const std::shared_ptr<QuicStream>& stream,
                      const SendFlags& eflags,
                      std::shared_ptr<const std::vector<uint8_t>> data);

        std::pair<SubscribeNodeSetId, bool> AddPeerSnsSourceNode(PeerSessionId in_peer_session_id,
                                                                 SubscribeNodeSetId in_sns_id,
                                                                 NodeIdValueType sub_node_id,
                                                                 uint8_t priority);

        std::pair<SubscribeNodeSetId, bool> AddSubscribeSourceNode(std::uint64_t full_name_hash,
                                                                   NodeIdValueType sub_node_id,
                                                                   uint8_t priority);

        std::pair<bool, bool> RemoveSubscribeSourceNode(std::uint64_t full_name_hash, NodeIdValueType sub_node_id);

        std::pair<bool, bool> RemovePeerSnsSourceNode(PeerSessionId in_peer_session_id,
                                                      SubscribeNodeSetId in_sns_id,
                                                      NodeIdValueType sub_node_id);

        void OnReady();
        void OnTransportClosed();
        void OnStream(uint64_t stream_id, bool bidirectional, std::vector<uint8_t> data, bool fin);
        void OnDatagram(std::vector<uint8_t> data);
        void OnStreamClosed(uint64_t stream_id, StreamClose flag);

        struct PendingData
        {
            bool is_new_stream{ false };
            uint64_t stream_id{ 0 };
            DataHeader header;
            std::shared_ptr<const std::vector<uint8_t>> data;
            uint64_t data_offset{ 0 };
            SendFlags flags;
        };

        /// Datagrams can arrive before the control message that creates their forwarding entry.
        void StashPending(PendingData data);
        std::vector<PendingData> TakePending(SubscribeNodeSetId sns_id);

      private:
        bool IsUsable() const { return connection_ != nullptr && !connection_closed_; }

        void SendConnect();
        void SendConnectOk() const;
        SubscribeNodeSetId NextSnsId();
        void SendControl(std::vector<uint8_t> msg) const;
        void ProcessControlMessage();
        bool ProcessReceivedData(std::uint64_t stream_id, std::shared_ptr<const std::vector<uint8_t>> data);
        QuicConnection::Handlers Handlers();

      public:
        std::string peer_host_;
        uint16_t peer_port_{ 0 };
        const Config& config_;
        const NodeInfo node_info_;
        NodeInfo remote_node_info_;

        struct Metrics
        {
            uint64_t srtt_us{ 0 };
        } metrics_;

      private:
        Engine& manager_;
        StatusValue status_{ StatusValue::kConnecting };

        bool is_inbound_{ false };
        bool connection_closed_{ false };

        std::map<std::uint64_t, SubscribeNodeSet> sub_sns_;
        std::map<std::pair<PeerSessionId, SubscribeNodeSetId>, SubscribeNodeSet> peer_sns_;
        SubscribeNodeSetId last_sns_id_{ 0 };

        std::shared_ptr<QuicStream> control_stream_;
        std::optional<std::uint64_t> control_stream_id_;
        std::vector<uint8_t> controL_msg_buffer_;
        std::map<std::uint64_t, DataHeader> rx_stream_headers_;
        std::map<std::uint64_t, std::vector<uint8_t>> rx_pending_;
        std::map<SubscribeNodeSetId, std::vector<PendingData>> pending_data_;

        std::shared_ptr<QuicConnection> connection_;
    };

} // namespace moq::peering
