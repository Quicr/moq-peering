// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <moq/peering/types.h>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <thread>

#include "forwarding_base.h"
#include "messages/data_header.h"
#include "peer_session.h"
#include "quic_transport.h"

namespace moq::peering {

    /**
     * @brief Internal peering engine
     *
     * @details Peer sessions call this directly. The public PeerManager forwards the application API here.
     */
    class Engine
    {
      public:
        friend class PeerSession;

        explicit Engine(Config config);
        ~Engine();

        void SetDelegate(Delegate* delegate);

        void NodeReceived(PeerSessionId peer_session_id, const NodeInfo& node_info, bool withdraw);
        void SubscribeInfoReceived(PeerSessionId peer_session_id, SubscribeInfo& subscribe_info, bool withdraw);
        void AnnounceInfoReceived(PeerSessionId peer_session_id, const AnnounceInfo& announce_info, bool withdraw);

        void SessionChanged(PeerSessionId peer_session_id,
                            PeerSession::StatusValue status,
                            const NodeInfo& remote_node_info);

        void ForwardPeerData(PeerSessionId peer_session_id,
                             bool is_new_stream,
                             uint64_t stream_id,
                             DataHeader data_header,
                             std::shared_ptr<const std::vector<uint8_t>> data,
                             uint64_t data_offset,
                             SendFlags eflags);

        void Announce(const TrackName& name, Announcement kind, bool withdraw = false);
        void Subscribe(const TrackName& name, const SubscribeParams& params);
        void UpdateSubscribe(const TrackName& name, const SubscribeParams& params);
        void Unsubscribe(uint64_t track_fullname_hash);

        enum class NodeChannelStatus : uint8_t
        {
            kOk = 0,
            kErrorExists,
        };

        NodeChannelStatus CreateNodeChannel(NodeIdValueType node_id);
        NodeChannelStatus CloseNodeChannel(NodeIdValueType node_id);
        NodeChannelStatus SendToNodeChannel(NodeIdValueType node_id, std::span<const uint8_t> data);

        std::set<NodeIdValueType> GetOriginNodeId(FullName full_name);

        bool HasSubscribers(uint64_t track_fullname_hash) const;

        void ForwardingBaseSyncPeer(PeerSession& peer_session);
        void SnsReceived(PeerSession& peer_session, const SubscribeNodeSet& sns, bool withdraw = false);

        void CloseStream(PeerSessionId peer_session_id,
                         SubscribeNodeSetId sns,
                         uint64_t stream_id,
                         uint64_t track_fullname_hash,
                         StreamClose flag);

        void EndSubgroup(std::uint64_t track_full_name_hash,
                         uint64_t group_id,
                         uint64_t subgroup_id,
                         bool reset = false);

        void SendData(std::uint64_t track_full_name_hash,
                      uint8_t priority,
                      uint32_t ttl,
                      DataType type,
                      uint64_t group_id,
                      uint64_t subgroup_id,
                      std::shared_ptr<const std::vector<uint8_t>> data);

      private:
        void NewPeerConnection(const std::shared_ptr<QuicConnection>& connection);
        void PeerConnectionClosed(uint64_t session_id);
        void CheckThread(int interval_ms);
        void CreatePeerSession(const std::string& host, uint16_t port);

        void PropagateNodeInfo(const NodeInfo& node_info, bool withdraw = false);
        void PropagateNodeInfo(PeerSessionId peer_session_id, const NodeInfo& node_info, bool withdraw = false);
        std::shared_ptr<PeerSession> GetPeerSession(PeerSessionId peer_session_id);

        static void CloseFibStreams(ForwardingBase::FibEntry& entry);

        Delegate* LoadDelegate() const { return delegate_.load(std::memory_order_acquire); }

        bool stop_{ false };
        std::mutex mutex_;
        std::shared_ptr<ForwardingBase> info_base_;
        std::atomic<Delegate*> delegate_{ nullptr };
        Config config_;
        NodeInfo node_info_;

        std::map<PeerSessionId, std::shared_ptr<PeerSession>> server_peer_sessions_;
        std::map<PeerSessionId, std::shared_ptr<PeerSession>> client_peer_sessions_;

        std::shared_ptr<QuicEndpoint> server_endpoint_;
        std::thread check_thr_;
    };

} // namespace moq::peering
