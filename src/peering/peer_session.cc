// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include "peer_session.h"
#include "common.h"
#include "engine.h"

#define LOGGER config_.logger
#include "peering/messages/connect.h"
#include "peering/messages/connect_response.h"
#include "peering/messages/node_info.h"
#include "peering/messages/subscribe_info.h"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace moq::peering {

    PeerSession::PeerSession(bool is_inbound,
                             const Config& cfg,
                             const NodeInfo& node_info,
                             std::string host,
                             uint16_t port,
                             Engine& manager)
      : peer_host_(std::move(host))
      , peer_port_(port)
      , config_(cfg)
      , node_info_(node_info)
      , manager_(manager)
      , is_inbound_(is_inbound)
    {
        controL_msg_buffer_.reserve(kControlMessageBufferSize);

        SPDLOG_LOGGER_DEBUG(LOGGER, "Starting peer session");
    }

    PeerSession::~PeerSession()
    {
        Disconnect();
        SPDLOG_LOGGER_DEBUG(LOGGER, "Removing peer session with {0}:{1}", peer_host_, peer_port_);
    }

    void PeerSession::Disconnect()
    {
        auto connection = std::move(connection_);
        if (!connection) {
            return;
        }

        connection->SetHandlers({});
        connection->Close();
        // A dial owns its packet loop. Stop it before this session, and the engine it calls, go away.
        // Accepted sessions share the server loop, which the engine stops after every session is closed.
        if (!is_inbound_) {
            connection->StopEndpoint();
        }
    }

    QuicConnection::Handlers PeerSession::Handlers()
    {
        auto self = shared_from_this();
        QuicConnection::Handlers handlers;
        handlers.on_ready = [self] { self->OnReady(); };
        handlers.on_closed = [self] { self->OnTransportClosed(); };
        handlers.on_stream = [self](uint64_t stream_id, bool bidirectional, std::vector<uint8_t> data, bool fin) {
            self->OnStream(stream_id, bidirectional, std::move(data), fin);
        };
        handlers.on_datagram = [self](std::vector<uint8_t> data) { self->OnDatagram(std::move(data)); };
        handlers.on_stream_closed = [self](uint64_t stream_id, StreamClose how) {
            self->OnStreamClosed(stream_id, how);
        };
        return handlers;
    }

    PeerSession::StatusValue PeerSession::Status()
    {
        return status_;
    }

    PeerSnapshot PeerSession::Snapshot()
    {
        auto connection = connection_;
        if (connection) {
            metrics_.srtt_us = connection->RttUs();
        }

        PeerSnapshot peer;
        peer.session_id = connection ? connection->Id() : 0;
        peer.origin = is_inbound_ ? PeerOrigin::kAccepted : PeerOrigin::kDialed;
        switch (status_) {
            case StatusValue::kConnecting:
                peer.status = PeerLinkStatus::kConnecting;
                break;
            case StatusValue::kConnected:
                peer.status = PeerLinkStatus::kConnected;
                break;
            case StatusValue::kDisconnected:
                peer.status = PeerLinkStatus::kDisconnected;
                break;
        }
        peer.host = peer_host_;
        peer.port = peer_port_;
        peer.identified = !remote_node_info_.contact.empty();
        if (peer.identified) {
            peer.node_id = remote_node_info_.id;
            peer.contact = remote_node_info_.contact;
            peer.node_type = remote_node_info_.type;
        }
        peer.srtt_us = metrics_.srtt_us;
        peer.connect_time_us = status_ == StatusValue::kConnected ? metrics_.connect_time_us : 0;
        return peer;
    }

    void PeerSession::MarkDisconnected()
    {
        status_ = StatusValue::kDisconnected;
        connection_closed_ = true;
        metrics_.connect_time_us = 0;
    }

    void PeerSession::NoteConnected()
    {
        if (metrics_.connect_time_us != 0) {
            return;
        }

        const auto now = std::chrono::system_clock::now().time_since_epoch();
        metrics_.connect_time_us =
          static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(now).count());
    }

    void PeerSession::ClearLocalState()
    {
        sub_sns_.clear();
        peer_sns_.clear();
        pending_data_.clear();
        rx_stream_headers_.clear();
        rx_pending_.clear();
        controL_msg_buffer_.clear();
        control_stream_.reset();
        control_stream_id_.reset();
    }

    void PeerSession::ForgetIngress(PeerSessionId peer_session_id)
    {
        for (auto it = peer_sns_.begin(); it != peer_sns_.end();) {
            if (it->first.first == peer_session_id) {
                it = peer_sns_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void PeerSession::Connect()
    {
        status_ = StatusValue::kConnecting;
        remote_node_info_ = {};
        metrics_.connect_time_us = 0;

        if (is_inbound_) {
            status_ = StatusValue::kConnected;
            NoteConnected();
            return;
        }

        if (connection_) {
            connection_->SetHandlers({});
            connection_->Close();
        }
        connection_ = nullptr;
        connection_closed_ = false;
        control_stream_ = nullptr;
        control_stream_id_.reset();

        peer_sns_.clear();
        rx_stream_headers_.clear();
        rx_pending_.clear();

        try {
            connection_ = QuicEndpoint::Dial(
              config_.tls_cert_filename, config_.tls_key_filename, peer_host_, peer_port_, Handlers());
        } catch (const std::exception& e) {
            SPDLOG_LOGGER_ERROR(LOGGER, "Failed to connect to peer {}:{} ({})", peer_host_, peer_port_, e.what());
            status_ = StatusValue::kDisconnected;
            return;
        }

        if (!connection_) {
            SPDLOG_LOGGER_ERROR(LOGGER, "Failed to connect to peer {}:{}", peer_host_, peer_port_);
            status_ = StatusValue::kDisconnected;
            return;
        }

        SPDLOG_LOGGER_DEBUG(LOGGER, "Created peer session {}", connection_->Id());
    }

    void PeerSession::Begin()
    {
        if (connection_ && !is_inbound_) {
            connection_->Start();
        }
    }

    void PeerSession::SetConnection(std::shared_ptr<QuicConnection> connection)
    {
        connection_ = std::move(connection);
    }

    void PeerSession::Attach(const std::shared_ptr<QuicConnection>& connection)
    {
        connection_ = connection;
        connection_->SetHandlers(Handlers());
    }

    SubscribeNodeSetId PeerSession::NextSnsId()
    {
        // Zero means unset, so it is skipped when the counter wraps
        if (last_sns_id_ >= kMaxSnsId) {
            last_sns_id_ = 0;
        }

        return ++last_sns_id_;
    }

    std::pair<SubscribeNodeSetId, bool> PeerSession::AddPeerSnsSourceNode(PeerSessionId in_peer_session_id,
                                                                          SubscribeNodeSetId in_sns_id,
                                                                          NodeIdValueType sub_node_id,
                                                                          uint8_t priority)
    {
        auto [it, new_ingress] = peer_sns_.try_emplace({ in_peer_session_id, in_sns_id });
        auto& sns = it->second;

        if (it->second.id == 0) {
            it->second.id = NextSnsId();
            it->second.priority = priority;
        }

        auto [__, is_new] = sns.nodes.emplace(sub_node_id);

        if (is_new and node_info_.id != sub_node_id) {
            SendSns(sns, false);
        }

        return { it->second.id, is_new };
    }

    std::pair<SubscribeNodeSetId, bool> PeerSession::AddSubscribeSourceNode(std::uint64_t full_name_hash,
                                                                            NodeIdValueType sub_node_id,
                                                                            uint8_t priority)
    {
        auto [it, _] = sub_sns_.try_emplace(full_name_hash);
        auto& sns = it->second;

        if (it->second.id == 0) {
            it->second.id = NextSnsId();
            it->second.priority = priority;
        }

        auto [__, is_new] = sns.nodes.emplace(sub_node_id);

        if (is_new) {
            SendSns(sns, false);
        }

        return { it->second.id, is_new };
    }

    std::pair<bool, bool> PeerSession::RemoveSubscribeSourceNode(std::uint64_t full_name_hash,
                                                                 NodeIdValueType sub_node_id)
    {
        bool node_removed{ false };
        bool sns_removed{ false };

        auto it = sub_sns_.find(full_name_hash);
        if (it != sub_sns_.end()) {
            auto& sns = it->second;

            node_removed = sns.nodes.erase(sub_node_id) ? true : false;

            if (sns.nodes.empty()) {
                sns_removed = true;

                SendSns(sns, true);

                sub_sns_.erase(it);
            }
        }

        return { node_removed, sns_removed };
    }

    std::pair<bool, bool> PeerSession::RemovePeerSnsSourceNode(PeerSessionId in_peer_session_id,
                                                               SubscribeNodeSetId in_sns_id,
                                                               NodeIdValueType sub_node_id)
    {
        bool node_removed{ false };
        bool sns_removed{ false };

        auto it = peer_sns_.find({ in_peer_session_id, in_sns_id });
        if (it != peer_sns_.end()) {
            auto& sns = it->second;

            if (sub_node_id == 0) { // Remove all
                SendSns(sns, true);
                peer_sns_.erase(it);
            }

            else { // Remove one
                node_removed = sns.nodes.erase(sub_node_id) ? true : false;

                if (sns.nodes.empty()) {
                    sns_removed = true;

                    SendSns(sns, true);

                    peer_sns_.erase(it);
                }
            }
        }

        return { node_removed, sns_removed };
    }

    std::shared_ptr<QuicStream> PeerSession::CreateStream(uint8_t priority) const
    {
        if (!IsUsable()) {
            return nullptr;
        }

        return connection_->OpenUnidirectional(priority);
    }

    void PeerSession::CloseStream(const std::shared_ptr<QuicStream>& stream, StreamClose flag)
    {
        if (!IsUsable() || stream == nullptr) {
            return;
        }

        switch (flag) {
            case StreamClose::kFin:
                connection_->Send(stream->id, {}, true);
                break;
            case StreamClose::kReset:
                connection_->Reset(stream->id);
                break;
            case StreamClose::kStopSending:
                connection_->StopSending(stream->id);
                break;
        }
    }

    void PeerSession::FinishStream(const std::shared_ptr<QuicStream>& stream)
    {
        if (stream == nullptr) {
            return;
        }

        // picoquic queues the FIN behind bytes already given to add_to_stream.
        if (status_ == StatusValue::kConnected && IsUsable()) {
            SendFlags eflags;
            eflags.reliable = true;
            eflags.close_stream = true;
            SendData(0, config_.object_ttl_ms, stream, eflags, std::make_shared<std::vector<uint8_t>>());
            return;
        }

        CloseStream(stream, StreamClose::kFin);
    }

    void PeerSession::SendData(uint8_t priority,
                               uint32_t ttl,
                               const std::shared_ptr<QuicStream>& stream,
                               const SendFlags& eflags,
                               std::shared_ptr<const std::vector<uint8_t>> data)
    {
        (void)priority;
        (void)ttl;

        if (status_ != StatusValue::kConnected || !IsUsable())
            return;

        if (!eflags.reliable) {
            connection_->SendDatagram(*data);
            return;
        }

        if (stream == nullptr) {
            return;
        }

        connection_->Send(stream->id, *data, eflags.close_stream);
    }

    void PeerSession::SendControl(std::vector<uint8_t> msg) const
    {
        if (!IsUsable() || control_stream_ == nullptr) {
            SPDLOG_LOGGER_DEBUG(
              LOGGER, "No control stream for peer conn_id {}, dropping control message", GetSessionId());
            return;
        }

        connection_->Send(control_stream_->id, msg, false);
    }

    void PeerSession::SendSns(const SubscribeNodeSet& sns, bool withdraw) const
    {
        if (status_ != StatusValue::kConnected || !IsUsable())
            return;

        SPDLOG_LOGGER_DEBUG(LOGGER, "Sending SNS id: {} set size: {} withdraw: {}", sns.id, sns.nodes.size(), withdraw);

        SendControl(sns.Serialize(true, withdraw));
    }

    void PeerSession::SendAnnounceInfo(const AnnounceInfo& announce_info, bool withdraw)
    {
        if (status_ != StatusValue::kConnected || !IsUsable())
            return;
        SPDLOG_LOGGER_DEBUG(LOGGER,
                            "Sending announce info id: {} source_node_id: {} withdraw: {}",
                            announce_info.track.fullname_hash,
                            announce_info.track.source_node_id,
                            withdraw);

        SendControl(announce_info.Serialize(true, withdraw));
    }

    void PeerSession::SendSubscribeInfo(SubscribeInfo& subscribe_info, bool withdraw) const
    {
        if (status_ != StatusValue::kConnected || !IsUsable())
            return;
        SPDLOG_LOGGER_DEBUG(
          LOGGER,
          "Sending subscribe fullname: {} source_node_id: {} withdraw: {} priority: {} new_group: {}",
          subscribe_info.details.track_hash.track_fullname_hash,
          NodeId().Value(subscribe_info.track.source_node_id),
          withdraw,
          subscribe_info.details.priority,
          subscribe_info.details.new_group_request_id.has_value() ? *subscribe_info.details.new_group_request_id : -1);

        SendControl(subscribe_info.Serialize(true, withdraw, node_info_.id == subscribe_info.track.source_node_id));
    }

    void PeerSession::SendNodeInfo(const NodeInfo& node_info, bool withdraw) const
    {
        if (status_ != StatusValue::kConnected || !IsUsable())
            return;
        SPDLOG_LOGGER_DEBUG(LOGGER, "Sending node info id: {}", NodeId().Value(node_info.id));

        SendControl(node_info.Serialize(true, withdraw));
    }

    void PeerSession::SendConnect()
    {
        peering::Connect connect;
        connect.mode = PeerMode::kBoth;
        connect.node_info = node_info_;

        peer_sns_.clear();

        SPDLOG_LOGGER_DEBUG(LOGGER, "Sending connect length: {}", connect.Serialize().size());

        SendControl(connect.Serialize());
    }

    void PeerSession::SendConnectOk() const
    {
        ConnectResponse connect_resp;
        connect_resp.error = ProtocolError::kNoError;
        connect_resp.node_info = node_info_;
        SPDLOG_LOGGER_DEBUG(LOGGER, "Sending connect ok length: {}", connect_resp.Serialize().size());

        SendControl(connect_resp.Serialize());
    }

    void PeerSession::ProcessControlMessage()
    try {
        if (controL_msg_buffer_.size() >= kCommonHeadersSize) {
            auto cursor_it = controL_msg_buffer_.begin();
            auto bytes = std::span<uint8_t>{ cursor_it, cursor_it + kCommonHeadersSize };
            cursor_it += kCommonHeadersSize;

            // TODO(tievens): Implement version checking and error handling
            auto version = bytes.front();
            auto type = ValueOf<uint16_t>({ bytes.begin() + 1, bytes.begin() + 3 });
            auto data_len = ValueOf<uint32_t>({ bytes.begin() + 3, bytes.begin() + 7 });

            if (controL_msg_buffer_.size() >= kCommonHeadersSize + data_len) {
                auto msg_bytes = std::span{ cursor_it, cursor_it + data_len };

                // Control Message
                switch (static_cast<MsgType>(type)) {
                    case MsgType::kConnect: {
                        peering::Connect connect(msg_bytes);
                        SPDLOG_LOGGER_DEBUG(config_.logger,
                                            "Connect from id: {} contact: {} mode: {} version: {}",
                                            NodeId().Value(connect.node_info.id),
                                            connect.node_info.contact,
                                            static_cast<int>(connect.mode),
                                            static_cast<int>(version));
                        remote_node_info_ = connect.node_info;

                        const bool became_connected = status_ != StatusValue::kConnected;
                        status_ = StatusValue::kConnected;
                        if (became_connected) {
                            NoteConnected();
                        }

                        manager_.NodeReceived(GetSessionId(), connect.node_info, false);
                        if (became_connected) {
                            manager_.SessionChanged(GetSessionId(), status_, remote_node_info_);
                        }

                        SendConnectOk();

                        manager_.ForwardingBaseSyncPeer(*this);
                        break;
                    }

                    case MsgType::kConnectResponse: {
                        ConnectResponse connect_resp(msg_bytes);

                        if (connect_resp.error == ProtocolError::kNoError) {
                            remote_node_info_ = *connect_resp.node_info;
                            manager_.NodeReceived(GetSessionId(), *connect_resp.node_info, false);

                            manager_.ForwardingBaseSyncPeer(*this);

                        } else {
                            SPDLOG_LOGGER_DEBUG(config_.logger,
                                                "Connect error response from error: {}",
                                                static_cast<int>(connect_resp.error));
                        }
                        const bool became_connected = status_ != StatusValue::kConnected;
                        status_ = StatusValue::kConnected;
                        if (became_connected) {
                            NoteConnected();
                            manager_.SessionChanged(GetSessionId(), status_, remote_node_info_);
                        }

                        manager_.ForwardingBaseSyncPeer(*this);
                        break;
                    }

                    case MsgType::kSubscribeNodeSetAdvertised: {
                        SubscribeNodeSet sns(msg_bytes, false);

                        if (config_.debug) {
                            std::ostringstream sns_nodes;
                            for (const auto& node : sns.nodes) {
                                sns_nodes << NodeId().Value(node) << ", ";
                            }

                            SPDLOG_LOGGER_DEBUG(LOGGER, "SNS received id: {} nodes: {}", sns.id, sns_nodes.str());
                        }

                        manager_.SnsReceived(*this, sns, false);
                        break;
                    }

                    case MsgType::kSubscribeNodeSetWithdrawn: {
                        SubscribeNodeSet sns(msg_bytes, true);
                        SPDLOG_LOGGER_DEBUG(LOGGER, "SNS withdrawn received id: {}", sns.id);
                        manager_.SnsReceived(*this, sns, true);
                        break;
                    }

                    case MsgType::kNodeInfoAdvertise: {
                        NodeInfo node_info(msg_bytes);
                        manager_.NodeReceived(GetSessionId(), node_info, false);
                        break;
                    }

                    case MsgType::kNodeInfoWithdrawn: {
                        NodeInfo node_info(msg_bytes);
                        manager_.NodeReceived(GetSessionId(), node_info, true);
                        break;
                    }

                    case MsgType::kSubscribeInfoAdvertised: {
                        SubscribeInfo subscribe_info(msg_bytes);
                        manager_.SubscribeInfoReceived(GetSessionId(), subscribe_info, false);
                        break;
                    }

                    case MsgType::kSubscribeInfoWithdrawn: {
                        SubscribeInfo subscribe_info(msg_bytes);
                        manager_.SubscribeInfoReceived(GetSessionId(), subscribe_info, true);
                        break;
                    }

                    case MsgType::kAnnounceInfoAdvertised: {
                        AnnounceInfo announce_info(msg_bytes);
                        manager_.AnnounceInfoReceived(GetSessionId(), announce_info, false);
                        break;
                    }

                    case MsgType::kAnnounceInfoWithdrawn: {
                        AnnounceInfo announce_info(msg_bytes);
                        manager_.AnnounceInfoReceived(GetSessionId(), announce_info, true);
                        break;
                    }

                    default: {
                        SPDLOG_LOGGER_DEBUG(config_.logger, "Invalid message type {}", static_cast<int>(type));
                    }
                }

                controL_msg_buffer_.erase(controL_msg_buffer_.begin(), cursor_it + data_len);
            }
        }
    } catch (const std::exception& e) {
        SPDLOG_LOGGER_ERROR(config_.logger, "Unable to parse control message: {}", e.what());
        controL_msg_buffer_.clear();
    }

    bool PeerSession::ProcessReceivedData(std::uint64_t stream_id, std::shared_ptr<const std::vector<uint8_t>> data)
    {
        // TODO(tievens): Update to not buffer when node type is Via

        const SendFlags eflags{ .reliable = true, .close_stream = false };

        const auto header_it = rx_stream_headers_.find(stream_id);

        // NEW STREAM - parse start of stream headers
        if (header_it == rx_stream_headers_.end()) {
            if (data->empty() || data->size() < data->front()) {
                SPDLOG_LOGGER_DEBUG(
                  LOGGER,
                  "Received new data object stream id: {}, not enough bytes yet to read headers {} > {}",
                  stream_id,
                  data->empty() ? 0 : data->front(),
                  data->size());
                return false; // Not enough bytes to parse the headers, wait till more arrives
            }

            const auto hdr_len = data->front();

            auto& data_header = rx_stream_headers_[stream_id];
            data_header.Deserialize(*data);

            // Pipeline forward to other peers.
            manager_.ForwardPeerData(GetSessionId(), true, stream_id, data_header, data, hdr_len, eflags);

            return true;
        }

        // Pipeline forward to other peers. Not all data may have been popped, so only forward popped data
        manager_.ForwardPeerData(GetSessionId(), false, stream_id, header_it->second, data, 0, eflags);

        return true;
    }

    void PeerSession::StashPending(PendingData data)
    {
        const auto sns_id = data.header.sns_id;
        pending_data_[sns_id].push_back(std::move(data));
    }

    std::vector<PeerSession::PendingData> PeerSession::TakePending(SubscribeNodeSetId sns_id)
    {
        std::vector<PendingData> pending;
        if (auto it = pending_data_.find(sns_id); it != pending_data_.end()) {
            pending = std::move(it->second);
            pending_data_.erase(it);
        }
        return pending;
    }

    void PeerSession::OnReady()
    {
        const auto conn_id = GetSessionId();
        metrics_.srtt_us = connection_ ? connection_->RttUs() : 0;

        if (is_inbound_) {
            SPDLOG_LOGGER_DEBUG(LOGGER, "Peer conn_id {0} is ready", conn_id);
            if (status_ != StatusValue::kConnected) {
                status_ = StatusValue::kConnected;
                NoteConnected();
                manager_.SessionChanged(GetSessionId(), status_, remote_node_info_);
            }
            return;
        }

        SPDLOG_LOGGER_DEBUG(LOGGER, "Peer conn_id {0} is ready, sending connect message", conn_id);
        control_stream_ = connection_->OpenBidirectional(0);
        if (control_stream_) {
            control_stream_id_ = control_stream_->id;
        }
        SendConnect();
    }

    void PeerSession::OnTransportClosed()
    {
        if (connection_closed_) {
            return;
        }
        connection_closed_ = true;
        status_ = StatusValue::kDisconnected;
        metrics_.connect_time_us = 0;
        const auto session_id = GetSessionId();
        SPDLOG_LOGGER_DEBUG(LOGGER, "Peer conn_id {0} is disconnected", session_id);
        manager_.SessionChanged(session_id, status_, remote_node_info_);
        if (is_inbound_) {
            manager_.PeerConnectionClosed(session_id);
        }
    }

    void PeerSession::OnStream(uint64_t stream_id, bool bidirectional, std::vector<uint8_t> data, bool fin)
    {
        (void)fin;
        if (!IsUsable()) {
            return;
        }

        if (bidirectional) {
            control_stream_ = std::make_shared<QuicStream>();
            control_stream_->id = stream_id;
            control_stream_->bidirectional = true;
            control_stream_id_ = stream_id;

            if (!data.empty()) {
                controL_msg_buffer_.insert(controL_msg_buffer_.end(), data.begin(), data.end());
            }
            for (;;) {
                const auto buffered = controL_msg_buffer_.size();
                ProcessControlMessage();
                if (controL_msg_buffer_.size() == buffered) {
                    break;
                }
            }
            return;
        }

        std::shared_ptr<std::vector<uint8_t>> payload;
        if (!rx_stream_headers_.contains(stream_id)) {
            auto& pending = rx_pending_[stream_id];
            pending.insert(pending.end(), data.begin(), data.end());
            if (pending.empty() || pending.size() < pending.front()) {
                return;
            }
            payload = std::make_shared<std::vector<uint8_t>>(std::move(pending));
            rx_pending_.erase(stream_id);
        } else if (!data.empty()) {
            payload = std::make_shared<std::vector<uint8_t>>(std::move(data));
        }

        if (payload && !payload->empty()) {
            ProcessReceivedData(stream_id, std::move(payload));
        }
    }

    void PeerSession::OnDatagram(std::vector<uint8_t> bytes)
    {
        const SendFlags eflags{ .reliable = false, .close_stream = false };

        if (!IsUsable() || bytes.empty()) {
            return;
        }

        auto data = std::make_shared<std::vector<uint8_t>>(std::move(bytes));
        DataHeader data_header(*data);
        manager_.ForwardPeerData(GetSessionId(), false, 0, data_header, data, data_header.header_len, eflags);

        SPDLOG_LOGGER_TRACE(LOGGER,
                            "Received dgram sns_id: {} track_full_name: {} data size: {}",
                            data_header.sns_id,
                            data_header.track_full_name_hash,
                            data->size());
    }

    void PeerSession::OnStreamClosed(uint64_t stream_id, StreamClose flag)
    {
        const auto conn_id = GetSessionId();
        rx_pending_.erase(stream_id);

        if (control_stream_ != nullptr && control_stream_id_.has_value() && *control_stream_id_ == stream_id) {
            control_stream_ = nullptr;
            control_stream_id_.reset();
        }

        if (const auto header_it = rx_stream_headers_.find(stream_id); header_it != rx_stream_headers_.end()) {
            const auto& data_header = header_it->second;

            SPDLOG_LOGGER_DEBUG(LOGGER,
                                "Peer stream closed conn_id {} stream id: {} flag: {} track fullname hash: {}",
                                conn_id,
                                stream_id,
                                static_cast<int>(flag),
                                data_header.track_full_name_hash);
            manager_.CloseStream(conn_id, data_header.sns_id, stream_id, data_header.track_full_name_hash, flag);

            rx_stream_headers_.erase(header_it);

        } else {
            SPDLOG_LOGGER_DEBUG(LOGGER,
                                "Peer conn_id {} stream id: {} flag: {} closed without having existing state",
                                conn_id,
                                stream_id,
                                static_cast<int>(flag));
        }
    }

}