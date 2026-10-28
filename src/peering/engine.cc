// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#include "engine.h"
#include "name.h"

#include <peering/messages/data_header.h>

#include <spdlog/sinks/stdout_color_sinks.h>

#include <chrono>

#define LOGGER config_.logger

namespace moq::peering {
    namespace {
        void ApplySubscribeAttributes(SubscribeInfo& info, const SubscribeParams& params)
        {
            info.details.priority = params.priority;
            info.details.delivery_timeout = params.delivery_timeout_ms;
            info.details.expires = params.expires_ms;
            info.details.forward = params.forward;
            info.details.new_group_request_id = params.new_group_request_id;
        }

        SubscribeParams ToParams(const SubscribeInfo& info)
        {
            SubscribeParams params;
            params.priority = info.details.priority;
            params.delivery_timeout_ms = info.details.delivery_timeout;
            params.expires_ms = info.details.expires;
            params.forward = static_cast<uint8_t>(info.details.forward);
            params.new_group_request_id = info.details.new_group_request_id;
            return params;
        }

        TrackName ToTrackName(const NameSpace& name_space, const std::vector<uint8_t>& name)
        {
            TrackName out;
            out.name = name;
            for (const auto& entry : name_space.GetEntries()) {
                out.name_space.emplace_back(entry.begin(), entry.end());
            }
            return out;
        }

        NameSpace ToNamespace(const std::vector<std::vector<uint8_t>>& entries)
        {
            if (entries.empty()) {
                return {};
            }
            return NameSpace(entries);
        }

        FullName ToFullName(const TrackName& name)
        {
            return { ToNamespace(name.name_space), name.name };
        }

        ForwardingBase::StreamKey SubgroupStreamKey(uint64_t group_id, uint64_t subgroup_id)
        {
            return { .a = group_id, .b = subgroup_id };
        }

        ForwardingBase::StreamKey IngressStreamKey(uint64_t stream_id)
        {
            return { .a = stream_id, .b = 0 };
        }

        void AdvanceSeqIfUnchanged(SubscribeInfo& info, uint16_t seq_before)
        {
            if (info.details.seq != seq_before) {
                return;
            }

            info.details.seq =
              info.details.seq < 0xFFFF ? static_cast<uint16_t>(info.details.seq + 1) : static_cast<uint16_t>(0);
        }
    }

    // ------------------------------------------------------------
    // Methods used by peer session to feedback info and actions
    // ------------------------------------------------------------

    void Engine::NodeReceived(PeerSessionId peer_session_id, const NodeInfo& node_info, bool withdraw)
    try {
        SPDLOG_LOGGER_INFO(LOGGER,
                           "Node peer_session_id: {} received id: {} contact: {} should delete = {}",
                           peer_session_id,
                           NodeId().Value(node_info.id),
                           node_info.contact,
                           withdraw);

        auto peer_session = GetPeerSession(peer_session_id);

        if (not withdraw) {
            if (info_base_->AddNode(peer_session, node_info)) {
                // Add peer to path before advertising node
                auto adv_node_info = node_info;
                adv_node_info.path.push_back({ adv_node_info.id, peer_session->metrics_.srtt_us });
                PropagateNodeInfo(adv_node_info);
            }
        } else {
            info_base_->RemoveNode(peer_session_id, node_info.id);

            auto adv_node_info = node_info;
            adv_node_info.path.push_back({ peer_session->node_info_.id, peer_session->metrics_.srtt_us });
            PropagateNodeInfo(adv_node_info, true);
        }
    } catch (const std::exception&) {
        SPDLOG_LOGGER_DEBUG(LOGGER,
                            "Cannot find peer session {} to process node info received id: {} contact: {}",
                            peer_session_id,
                            NodeId().Value(node_info.id),
                            node_info.contact);
    }

    bool Engine::HasSubscribers(uint64_t track_fullname_hash) const
    {
        std::lock_guard lock(info_base_->mutex_);
        for (auto it = info_base_->client_fib_.lower_bound({ track_fullname_hash, 0 });
             it != info_base_->client_fib_.end();
             ++it) {
            auto& [key, fib] = *it;

            if (key.first != track_fullname_hash)
                break;

            return true;
        }

        return false;
    }

    void Engine::SubscribeInfoReceived(PeerSessionId peer_session_id, SubscribeInfo& subscribe_info, bool withdraw)
    try {
        SPDLOG_LOGGER_INFO(
          LOGGER,
          "Subscribe info received peer_session_id: {} fullname: {} namespace: {} source_node: {} withdraw: {}",
          peer_session_id,
          subscribe_info.details.track_hash.track_fullname_hash,
          subscribe_info.details.track_hash.track_namespace_hash,
          NodeId().Value(subscribe_info.track.source_node_id),
          withdraw);

        std::lock_guard ib_lock(info_base_->mutex_);

        std::shared_ptr<PeerSession> peer_session;
        if (auto server_it = server_peer_sessions_.find(peer_session_id); server_it != server_peer_sessions_.end()) {
            peer_session = server_it->second;
        } else if (auto client_it = client_peer_sessions_.find(peer_session_id);
                   client_it != client_peer_sessions_.end()) {
            peer_session = client_it->second;
        }
        if (!peer_session) {
            return;
        }

        // A relay learns its own subscribe again when two sessions exist toward the next hop.
        // Installing that echo as a forwarding entry makes HasSubscribers stay true after the
        // local client leaves, so the upstream subscribe is never withdrawn and the publisher
        // keeps sending to a peer.
        if (subscribe_info.track.source_node_id == node_info_.id) {
            SPDLOG_LOGGER_DEBUG(LOGGER,
                                "Ignoring echoed subscribe fullname: {} withdraw: {}",
                                subscribe_info.details.track_hash.track_fullname_hash,
                                withdraw);
            return;
        }

        const auto is_updated =
          withdraw ? info_base_->RemoveSubscribe(subscribe_info) : info_base_->AddSubscribe(subscribe_info);

        if (is_updated) {
            for (const auto& sess : client_peer_sessions_) {
                if (peer_session_id != sess.first)
                    sess.second->SendSubscribeInfo(subscribe_info, withdraw);
            }

            for (const auto& sess : server_peer_sessions_) {
                if (peer_session_id != sess.first)
                    sess.second->SendSubscribeInfo(subscribe_info, withdraw);
            }
        }

        /*
         * On subscribe, check if there are client announcements that match it. If so,
         * find best peer session and update peer session with subscribe node id
         * and send notification to client manager that there is a subscribe.
         */
        if (not withdraw) {
            uint64_t update_ref = rand();

            const auto priority = subscribe_info.details.priority;
            auto bp_it = info_base_->nodes_best_.find(subscribe_info.track.source_node_id);
            if (bp_it != info_base_->nodes_best_.end()) {
                const auto best_session = bp_it->second.lock();
                if (best_session) {
                    SPDLOG_LOGGER_DEBUG(
                      LOGGER,
                      "Best peer session for subscribe fullname: {} source_node: {} is via peer_session_id: {}",
                      subscribe_info.details.track_hash.track_fullname_hash,
                      subscribe_info.track.source_node_id,
                      best_session->GetSessionId());

                    if (auto [sns_id, is_new] =
                          best_session->AddSubscribeSourceNode(subscribe_info.details.track_hash.track_fullname_hash,
                                                               subscribe_info.track.source_node_id,
                                                               priority);
                        is_new) {
                        SPDLOG_LOGGER_INFO(
                          LOGGER,
                          "New source added to peer session for subscribe fullname: {} source_node: {} is "
                          "via peer_session_id: {} sns_id: {}",
                          subscribe_info.details.track_hash.track_fullname_hash,
                          subscribe_info.track.source_node_id,
                          best_session->GetSessionId(),
                          sns_id);

                        // Key is the egress session. SendData uses that session, and withdraw removes it.
                        if (auto [_, inserted] = info_base_->client_fib_.try_emplace(
                              { subscribe_info.details.track_hash.track_fullname_hash, best_session->GetSessionId() },
                              ForwardingBase::FibEntry{ update_ref, {}, sns_id, bp_it->second });
                            inserted) {
                            SPDLOG_LOGGER_INFO(LOGGER,
                                               "New subscribe fullname: {}, sending subscribe to client manager",
                                               subscribe_info.details.track_hash.track_fullname_hash);
                        }
                    }
                }
            }

            if (auto* delegate = LoadDelegate()) {
                SPDLOG_LOGGER_DEBUG(LOGGER,
                                    "Notifying delegate of subscribe fullname: {} new_group_request: {}",
                                    subscribe_info.details.track_hash.track_fullname_hash,
                                    subscribe_info.details.new_group_request_id.has_value()
                                      ? static_cast<std::int64_t>(*subscribe_info.details.new_group_request_id)
                                      : std::int64_t{ -1 });
                delegate->OnPeerSubscribe(ToTrackName(subscribe_info.track.name_space, subscribe_info.track.name),
                                          subscribe_info.details.track_hash.track_fullname_hash,
                                          ToParams(subscribe_info));
            }
        } else {
            const auto track_hash = subscribe_info.details.track_hash.track_fullname_hash;
            const auto source_id = subscribe_info.track.source_node_id;

            // The SNS may sit on a session that is no longer nodes_best_. Drop the source everywhere
            // so the next hop withdraws its peer forwarding entry and stops sending.
            auto drop_source = [&](const std::shared_ptr<PeerSession>& session) {
                if (!session) {
                    return;
                }

                const auto [node_removed, sns_removed] = session->RemoveSubscribeSourceNode(track_hash, source_id);
                if (!node_removed && !sns_removed) {
                    return;
                }

                if (!sns_removed) {
                    return;
                }

                SPDLOG_LOGGER_INFO(LOGGER,
                                   "No subscribe nodes left via peer session {}, removed subscribe fullname: {}",
                                   session->GetSessionId(),
                                   track_hash);

                for (auto fib_it = info_base_->client_fib_.lower_bound({ track_hash, 0 });
                     fib_it != info_base_->client_fib_.end();) {
                    if (fib_it->first.first != track_hash) {
                        break;
                    }

                    const auto egress = fib_it->second.peer_session.lock();
                    const bool same_session = fib_it->first.second == session->GetSessionId() ||
                                              (egress && egress->GetSessionId() == session->GetSessionId());
                    if (!same_session) {
                        ++fib_it;
                        continue;
                    }

                    CloseFibStreams(fib_it->second);
                    fib_it = info_base_->client_fib_.erase(fib_it);
                }
            };

            for (const auto& [_, session] : client_peer_sessions_) {
                drop_source(session);
            }
            for (const auto& [_, session] : server_peer_sessions_) {
                drop_source(session);
            }

            bool remote_subscribers{ false };
            if (const auto sub_it = info_base_->subscribes_.find(track_hash); sub_it != info_base_->subscribes_.end()) {
                for (const auto& [id, _] : sub_it->second) {
                    if (id != node_info_.id) {
                        remote_subscribers = true;
                        break;
                    }
                }
            }

            if (!remote_subscribers) {
                for (auto fib_it = info_base_->client_fib_.lower_bound({ track_hash, 0 });
                     fib_it != info_base_->client_fib_.end();) {
                    if (fib_it->first.first != track_hash) {
                        break;
                    }
                    CloseFibStreams(fib_it->second);
                    fib_it = info_base_->client_fib_.erase(fib_it);
                }

                SPDLOG_LOGGER_INFO(LOGGER, "No peers left for subscribe fullname: {}", track_hash);
            }

            if (auto* delegate = LoadDelegate()) {
                // A leftover fib is not a subscriber. The publisher stops when no remote node
                // still wants the track.
                delegate->OnPeerUnsubscribe(track_hash, remote_subscribers);
            }
        }

    } catch (const std::exception& e) {
        SPDLOG_LOGGER_ERROR(LOGGER, "Caught exception during subscribe info received: {}", e.what());
        // ignore
    }

    void Engine::AnnounceInfoReceived(PeerSessionId peer_session_id, const AnnounceInfo& announce_info, bool withdraw)
    try {
        auto th = TrackHash(announce_info.track.name_space, announce_info.track.name);
        SPDLOG_LOGGER_INFO(LOGGER,
                           "Announce info received peer_session_id: {} namespace hash: {} name hash: {} fullname hash: "
                           "{} == {} withdraw: {} flags: {}",
                           peer_session_id,
                           th.track_namespace_hash,
                           th.track_name_hash,
                           th.track_fullname_hash,
                           announce_info.track.fullname_hash,
                           withdraw,
                           static_cast<int>(announce_info.details.flags));

        auto peer_session = GetPeerSession(peer_session_id);
        if (not withdraw && !info_base_->AddAnnounce(announce_info)) {
            // Don't send to other peers if we have seen this before (loop)
            return;
        }

        if (withdraw && !info_base_->RemoveAnnounce(announce_info)) {
            // Don't send to other peers if we don't have state (loop)
            return;
        }

        for (const auto& sess : client_peer_sessions_) {
            if (peer_session_id != sess.first)
                sess.second->SendAnnounceInfo(announce_info, withdraw);
        }

        for (const auto& sess : server_peer_sessions_) {
            if (peer_session_id != sess.first)
                sess.second->SendAnnounceInfo(announce_info, withdraw);
        }

        if (auto* delegate = LoadDelegate()) {
            const auto name = ToTrackName(announce_info.track.name_space, announce_info.track.name);
            if (announce_info.details.flags & 1) {
                delegate->OnPeerNamespace(name.name_space, withdraw);
            } else {
                delegate->OnPeerTrack(name, withdraw);
            }
        }

    } catch (const std::exception&) {
        // ignore
    }

    void Engine::SessionChanged(PeerSessionId peer_session_id,
                                PeerSession::StatusValue status,
                                [[maybe_unused]] const NodeInfo& remote_node_info)
    {
        switch (status) {
            case PeerSession::StatusValue::kConnected: {
                SPDLOG_LOGGER_INFO(LOGGER, "Peer session connected peer_session_id: {}", peer_session_id);
                if (auto* delegate = LoadDelegate()) {
                    delegate->OnPeerUp(peer_session_id);
                }
                break;
            }
            case PeerSession::StatusValue::kConnecting:
                break;

            default: {
                SPDLOG_LOGGER_INFO(LOGGER, "Peer session not connected peer_session_id: {}", peer_session_id);
                if (auto* delegate = LoadDelegate()) {
                    delegate->OnPeerDown(peer_session_id);
                }

                PropagateNodeInfo(remote_node_info, true);

                if (!stop_)
                    info_base_->PurgePeerSessionInfo(peer_session_id);

                // Remove or find new best peer for subscribe info
                std::vector<SubscribeInfo> remove_sub;
                std::vector<std::pair<PeerSessionId, SubscribeInfo>> update_sub;

                std::unique_lock ib_lock(info_base_->mutex_);
                for (const auto& [_, by_source] : info_base_->subscribes_) {
                    for (const auto& [source_id, si] : by_source) {
                        if (source_id == remote_node_info.id) {
                            remove_sub.emplace_back(si);
                            continue;
                        }

                        // This session may be the path toward the subscriber. Repath, or withdraw that subscribe.
                        auto cfib_it =
                          info_base_->client_fib_.find({ si.details.track_hash.track_fullname_hash, peer_session_id });
                        if (cfib_it == info_base_->client_fib_.end()) {
                            continue;
                        }

                        info_base_->client_fib_.erase(cfib_it);

                        // Same recursive mutex. Keep it held so `si` cannot be freed by another peering thread.
                        const auto best_peer = info_base_->GetBestPeerSession(si.track.source_node_id);
                        if (const auto peer_sess = best_peer.lock()) {
                            update_sub.emplace_back(peer_sess->GetSessionId(), si);
                        } else {
                            remove_sub.emplace_back(si);
                        }
                    }
                }
                ib_lock.unlock();

                for (auto& si : remove_sub) {
                    SubscribeInfoReceived(peer_session_id, si, true);
                }

                for (auto& [id, si] : update_sub) {
                    SubscribeInfoReceived(id, si, false);
                }

                // Remove all announces if no active peering sessions exists
                bool remove_announce{ true };
                for (const auto& [id, peer_sess] : client_peer_sessions_) {
                    if (peer_sess->Status() == PeerSession::StatusValue::kConnected) {
                        remove_announce = false;
                        break;
                    }
                }

                if (remove_announce) {
                    for (const auto& [id, peer_sess] : server_peer_sessions_) {
                        if (peer_sess->Status() == PeerSession::StatusValue::kConnected) {
                            remove_announce = false;
                            break;
                        }
                    }
                }

                if (remove_announce) {
                    info_base_->announces_.clear();
                }

                break;
            }
        }
    }

    void Engine::ForwardPeerData(PeerSessionId peer_session_id,
                                 bool is_new_stream,
                                 uint64_t stream_id,
                                 DataHeader data_header,
                                 std::shared_ptr<const std::vector<uint8_t>> data,
                                 uint64_t data_offset,
                                 SendFlags eflags)
    {
        // Opening a QUIC stream waits on that connection's packet thread. The forwarding lock cannot
        // be held across that wait: the other thread takes the same lock from its own callback.
        struct Step
        {
            bool to_delegate{ false };
            std::uint64_t track_hash{ 0 };
            std::shared_ptr<const std::vector<uint8_t>> client_data;

            std::shared_ptr<PeerSession> session;
            PeerSessionId egress_id{ 0 };
            std::shared_ptr<QuicStream> stream;
            bool open_stream{ false };
            ForwardingBase::StreamKey key{};
            std::shared_ptr<std::vector<uint8_t>> data;
        };

        std::vector<Step> steps;
        bool stash = false;

        {
            std::lock_guard lock(info_base_->mutex_);
            auto it = info_base_->peer_fib_.find({ peer_session_id, data_header.sns_id });
            if (it == info_base_->peer_fib_.end()) {
                stash = true;
            } else {
                // TODO(tievens): Replace data_out with new transport multiple data
                for (auto& [out_peer_sess_id, entry] : it->second) {
                    if (out_peer_sess_id == peer_session_id)
                        continue; // Skip; don't send back to same peer or if it's self

                    if (out_peer_sess_id == 0) { // self; Client manager is interested
                        // TODO(tievens): Consider maintaining a client specific si map to avoid second map lookup
                        const auto sub_it = info_base_->subscribes_.find(data_header.track_full_name_hash);
                        if (sub_it == info_base_->subscribes_.end()) {
                            continue;
                        }

                        const auto& si_it = sub_it->second.find(node_info_.id);
                        if (si_it == sub_it->second.end()) {
                            continue;
                        }

                        Step step;
                        step.to_delegate = true;
                        step.track_hash = si_it->second.details.track_hash.track_fullname_hash;
                        step.client_data = data;
                        if (data_offset != 0) {
                            step.client_data =
                              std::make_shared<std::vector<uint8_t>>(data->begin() + data_offset, data->end());
                        }
                        steps.push_back(std::move(step));
                        continue;
                    }

                    auto out_peer_sess = entry.peer_session.lock();
                    if (out_peer_sess == nullptr) {
                        continue;
                    }

                    Step step;
                    step.session = std::move(out_peer_sess);
                    step.egress_id = out_peer_sess_id;
                    step.data = std::make_shared<std::vector<uint8_t>>(data->begin(), data->end());

                    // Update SNS_ID if new stream header included or if datagram (both have sns_id)
                    if (is_new_stream || eflags.reliable == false) {
                        auto sns_id_bytes = BytesOf(entry.out_sns_id);
                        std::copy(sns_id_bytes.rbegin(), sns_id_bytes.rend(), step.data->begin() + 2);
                    }

                    if (eflags.reliable) {
                        step.key = IngressStreamKey(stream_id);
                        auto sid_it = entry.streams.find(step.key);
                        if (sid_it == entry.streams.end()) {
                            if (!is_new_stream) {
                                continue; // Ignore existing data and wait for start of new stream
                            }
                            step.open_stream = true;
                        } else {
                            step.stream = sid_it->second;
                        }
                    }

                    steps.push_back(std::move(step));
                }
            }
        }

        if (stash) {
            if (auto peer_sess = GetPeerSession(peer_session_id)) {
                peer_sess->StashPending(PeerSession::PendingData{
                  is_new_stream, stream_id, data_header, std::move(data), data_offset, eflags });
            }
            return;
        }

        for (auto& step : steps) {
            if (step.to_delegate) {
                if (auto* delegate = LoadDelegate()) {
                    if (eflags.reliable) {
                        delegate->OnPeerData(step.track_hash, is_new_stream, stream_id, step.client_data);
                    } else {
                        delegate->OnPeerData(step.track_hash, false, std::nullopt, step.client_data);
                    }
                }
                continue;
            }

            if (step.open_stream) {
                auto opened = step.session->CreateStream(data_header.priority);
                std::shared_ptr<QuicStream> discard;
                {
                    std::lock_guard lock(info_base_->mutex_);
                    const auto fib = info_base_->peer_fib_.find({ peer_session_id, data_header.sns_id });
                    if (fib == info_base_->peer_fib_.end() || opened == nullptr) {
                        discard = std::move(opened);
                    } else if (const auto entry = fib->second.find(step.egress_id); entry == fib->second.end()) {
                        discard = std::move(opened);
                    } else {
                        const auto [inserted_it, inserted] = entry->second.streams.try_emplace(step.key, opened);
                        if (!inserted) {
                            discard = std::move(opened);
                        }
                        step.stream = inserted_it->second;
                    }
                }
                if (discard) {
                    step.session->CloseStream(discard, StreamClose::kReset);
                }
                if (step.stream == nullptr) {
                    continue;
                }
            }

            step.session->SendData(data_header.priority, data_header.ttl, step.stream, eflags, std::move(step.data));
        }
    }

    std::set<NodeIdValueType> Engine::GetOriginNodeId(FullName full_name)
    {
        return info_base_->GetAnnounceIds(full_name.name_space, full_name.name, false);
    }

    void Engine::EndSubgroup(std::uint64_t track_full_name_hash, uint64_t group_id, uint64_t subgroup_id, bool reset)
    {
        std::lock_guard lock(info_base_->mutex_);
        const auto key = SubgroupStreamKey(group_id, subgroup_id);

        for (auto it = info_base_->client_fib_.lower_bound({ track_full_name_hash, 0 });
             it != info_base_->client_fib_.end();
             ++it) {
            auto& fib_entry = it->second;

            if (it->first.first != track_full_name_hash)
                break;

            if (const auto peer_sess = fib_entry.peer_session.lock()) {
                SPDLOG_LOGGER_TRACE(LOGGER,
                                    "Client end group: {} subgroup: {}, peer_session: {} egress SNS_ID: {}",
                                    group_id,
                                    subgroup_id,
                                    peer_sess->GetSessionId(),
                                    fib_entry.out_sns_id);

                auto stream_it = fib_entry.streams.find(key);
                if (stream_it != fib_entry.streams.end()) {
                    if (reset) {
                        peer_sess->CloseStream(stream_it->second, StreamClose::kReset);
                    } else {
                        peer_sess->FinishStream(stream_it->second);
                    }
                    fib_entry.streams.erase(stream_it);
                }
            }
        }
    }

    void Engine::SendData(std::uint64_t track_full_name_hash,
                          uint8_t priority,
                          uint32_t ttl,
                          DataType type,
                          uint64_t group_id,
                          uint64_t subgroup_id,
                          std::shared_ptr<const std::vector<uint8_t>> data)
    {
        // Same rule as ForwardPeerData: CreateStream waits on the peer connection's packet thread.
        struct Outgoing
        {
            std::shared_ptr<PeerSession> session;
            PeerSessionId session_id{ 0 };
            std::shared_ptr<QuicStream> stream;
            bool open_stream{ false };
            ForwardingBase::StreamKey key{};
            std::shared_ptr<std::vector<uint8_t>> data;
            SubscribeNodeSetId sns_id{ 0 };
        };

        std::vector<Outgoing> outgoing;
        SendFlags eflags;

        {
            std::lock_guard lock(info_base_->mutex_);

            DataHeader data_header;
            data_header.type = type;
            data_header.priority = priority;
            data_header.ttl = ttl;
            data_header.track_full_name_hash = track_full_name_hash;

            auto net_data = std::make_shared<std::vector<uint8_t>>(data_header.Serialize());
            net_data->insert(net_data->end(), data->begin(), data->end());

            bool set_sns_id{ false };
            switch (type) {
                case DataType::kDatagram:
                    eflags.reliable = false;
                    set_sns_id = true;
                    break;
                case DataType::kExistingStream:
                    eflags.reliable = true;
                    break;
                case DataType::kNewStream:
                    set_sns_id = true;
                    eflags.reliable = true;
                    break;
            }

            for (auto it = info_base_->client_fib_.lower_bound({ track_full_name_hash, 0 });
                 it != info_base_->client_fib_.end();
                 ++it) {
                auto& fib_entry = it->second;

                if (it->first.first != track_full_name_hash)
                    break;

                const auto peer_sess = fib_entry.peer_session.lock();
                if (!peer_sess) {
                    continue;
                }

                SPDLOG_LOGGER_TRACE(LOGGER,
                                    "Data object send, peer_session: {} egress SNS_ID: {} tfn_hash: {}",
                                    peer_sess->GetSessionId(),
                                    fib_entry.out_sns_id,
                                    track_full_name_hash);

                Outgoing out;
                out.session = peer_sess;
                out.session_id = it->first.second;
                out.sns_id = fib_entry.out_sns_id;
                out.data = net_data;
                if (set_sns_id) {
                    out.data = std::make_shared<std::vector<uint8_t>>(*net_data);
                    auto sns_id_bytes = BytesOf(fib_entry.out_sns_id);
                    std::copy(sns_id_bytes.rbegin(), sns_id_bytes.rend(), out.data->begin() + 2);
                }

                if (eflags.reliable) {
                    out.key = SubgroupStreamKey(group_id, subgroup_id);
                    auto stream_it = fib_entry.streams.find(out.key);
                    if (stream_it == fib_entry.streams.end()) {
                        if (data_header.type != DataType::kNewStream) {
                            continue;
                        }
                        out.open_stream = true;
                    } else {
                        out.stream = stream_it->second;
                        if (out.stream == nullptr) {
                            continue;
                        }
                    }
                }

                outgoing.push_back(std::move(out));
            }
        }

        for (auto& out : outgoing) {
            if (out.open_stream) {
                auto opened = out.session->CreateStream(priority);
                std::shared_ptr<QuicStream> discard;
                {
                    std::lock_guard lock(info_base_->mutex_);
                    const auto fib = info_base_->client_fib_.find({ track_full_name_hash, out.session_id });
                    if (fib == info_base_->client_fib_.end() || opened == nullptr) {
                        discard = std::move(opened);
                    } else {
                        const auto [inserted_it, inserted] = fib->second.streams.try_emplace(out.key, opened);
                        if (!inserted) {
                            discard = std::move(opened);
                        }
                        out.stream = inserted_it->second;

                        SPDLOG_LOGGER_TRACE(LOGGER,
                                            "Data object send, peer_session: {} egress SNS_ID: {} tfn_hash: {} "
                                            "group_id: {} subgroup_id: {} streams: {} data len: {}",
                                            out.session->GetSessionId(),
                                            out.sns_id,
                                            track_full_name_hash,
                                            group_id,
                                            subgroup_id,
                                            fib->second.streams.size(),
                                            out.data->size());
                    }
                }
                if (discard) {
                    out.session->CloseStream(discard, StreamClose::kReset);
                }
                if (out.stream == nullptr) {
                    continue;
                }
            }

            out.session->SendData(priority, ttl, out.stream, eflags, out.data);
        }
    }

    void Engine::Unsubscribe(uint64_t track_fullname_hash)
    {
        if (auto si = info_base_->GetSubscribe(track_fullname_hash, node_info_.id)) {
            info_base_->RemoveSubscribe(*si);

            for (const auto& sess : client_peer_sessions_) {
                SPDLOG_LOGGER_DEBUG(LOGGER,
                                    "Sending subscribe withdraw fullname: {} peer_session_id: {}",
                                    si->details.track_hash.track_fullname_hash,
                                    sess.first);
                sess.second->SendSubscribeInfo(*si, true);
            }

            for (const auto& sess : server_peer_sessions_) {
                SPDLOG_LOGGER_DEBUG(LOGGER,
                                    "Sending subscribe withdraw fullname: {} peer_session_id: {}",
                                    si->details.track_hash.track_fullname_hash,
                                    sess.first);
                sess.second->SendSubscribeInfo(*si, true);
            }
        }
    }

    void Engine::UpdateSubscribe(const TrackName& track_name, const SubscribeParams& params)
    {
        const auto track_full_name = ToFullName(track_name);
        const auto th = TrackHash(track_full_name);

        if (auto si = info_base_->GetSubscribe(th.track_fullname_hash, node_info_.id)) {
            ApplySubscribeAttributes(*si, params);

            const auto seq_before = si->details.seq;
            for (const auto& sess : client_peer_sessions_) {
                SPDLOG_LOGGER_DEBUG(LOGGER,
                                    "Sending subscribe update fullname: {} peer_session_id: {} priority: {} "
                                    "delivery_timeout: {} expires: {} forward: {} new_group: {}",
                                    th.track_fullname_hash,
                                    sess.first,
                                    params.priority,
                                    params.delivery_timeout_ms,
                                    params.expires_ms,
                                    params.forward,
                                    params.new_group_request_id.has_value() ? *params.new_group_request_id : -1);
                sess.second->SendSubscribeInfo(*si, false);
            }

            for (const auto& sess : server_peer_sessions_) {
                SPDLOG_LOGGER_DEBUG(LOGGER,
                                    "Sending subscribe update fullname: {} peer_session_id: {} priority: {} "
                                    "delivery_timeout: {} expires: {} forward: {} new_group: {}",
                                    th.track_fullname_hash,
                                    sess.first,
                                    params.priority,
                                    params.delivery_timeout_ms,
                                    params.expires_ms,
                                    params.forward,
                                    params.new_group_request_id.has_value() ? *params.new_group_request_id : -1);
                sess.second->SendSubscribeInfo(*si, false);
            }

            AdvanceSeqIfUnchanged(*si, seq_before);
            info_base_->AddSubscribe(*si);
        }
    }

    void Engine::Subscribe(const TrackName& track_name, const SubscribeParams& params)
    {
        const auto track_full_name = ToFullName(track_name);
        SubscribeInfo si;

        si.details.track_hash = TrackHash(track_full_name);
        si.track.fullname_hash = si.details.track_hash.track_fullname_hash;
        si.track.name_space = track_full_name.name_space;
        si.track.name = track_full_name.name;
        si.track.source_node_id = node_info_.id;
        ApplySubscribeAttributes(si, params);

        const auto seq_before = si.details.seq;
        for (const auto& sess : client_peer_sessions_) {
            SPDLOG_LOGGER_DEBUG(LOGGER,
                                "Sending subscribe fullname: {} peer_session_id: {}",
                                si.details.track_hash.track_fullname_hash,
                                sess.first);
            sess.second->SendSubscribeInfo(si, false);
        }

        for (const auto& sess : server_peer_sessions_) {
            SPDLOG_LOGGER_DEBUG(LOGGER,
                                "Sending subscribe fullname: {} peer_session_id: {}",
                                si.details.track_hash.track_fullname_hash,
                                sess.first);
            sess.second->SendSubscribeInfo(si, false);
        }

        AdvanceSeqIfUnchanged(si, seq_before);
        info_base_->AddSubscribe(si);
    }

    void Engine::Announce(const TrackName& track_name, Announcement kind, bool withdraw)
    {
        std::lock_guard lock(info_base_->mutex_);
        const auto track_full_name = ToFullName(track_name);
        const bool publish_namespace = kind == Announcement::kNamespace;
        AnnounceInfo ai;

        ai.track.name_space = track_full_name.name_space;
        ai.track.name = track_full_name.name;
        ai.track.source_node_id = node_info_.id;
        ai.details.flags = publish_namespace ? 1 : 0;

        auto th = TrackHash(track_full_name);
        ai.track.fullname_hash = th.track_fullname_hash;

        if (not withdraw) {
            info_base_->AddAnnounce(ai);
        } else {
            info_base_->RemoveAnnounce(ai);
        }

        for (const auto& sess : client_peer_sessions_) {
            SPDLOG_LOGGER_DEBUG(
              LOGGER,
              "Sending namespace hash: {} name hash: {} full_name_hash: {} to peer_session_id: {} withdraw: {}",
              th.track_namespace_hash,
              th.track_name_hash,
              th.track_fullname_hash,
              sess.first,
              withdraw);

            sess.second->SendAnnounceInfo(ai, withdraw);
        }

        for (const auto& sess : server_peer_sessions_) {
            SPDLOG_LOGGER_DEBUG(
              LOGGER,
              "Sending namespace hash: {} name hash: {} full_name_hash: {} to peer_session_id: {} withdraw: {}",
              th.track_namespace_hash,
              th.track_name_hash,
              th.track_fullname_hash,
              sess.first,
              withdraw);

            sess.second->SendAnnounceInfo(ai, withdraw);
        }

        if (not withdraw) {
            uint64_t update_ref = rand();

            // TODO: change to not iterate over all subscribes to find a match
            for (const auto& [ftn, sub_map] : info_base_->subscribes_) {

                if (sub_map.empty())
                    continue;

                for (const auto& si_it : sub_map) {
                    if (si_it.first == node_info_.id)
                        continue;
                    const auto& sub_info = si_it.second;

                    if (track_full_name.name_space.HasSamePrefix(sub_info.track.name_space)) {

                        if (sub_info.track.source_node_id == node_info_.id)
                            continue;

                        auto bp_it = info_base_->nodes_best_.find(sub_info.track.source_node_id);
                        if (bp_it != info_base_->nodes_best_.end()) {
                            const auto& peer_session = bp_it->second.lock();
                            SPDLOG_LOGGER_DEBUG(LOGGER,
                                                "Best peer session for subscribe fullname: {} source_node: {} is "
                                                "via peer_session_id: {}",
                                                sub_info.details.track_hash.track_fullname_hash,
                                                sub_info.track.source_node_id,
                                                peer_session->GetSessionId());

                            if (auto [sns_id, is_new] =
                                  peer_session->AddSubscribeSourceNode(sub_info.details.track_hash.track_fullname_hash,
                                                                       sub_info.track.source_node_id,
                                                                       sub_info.details.priority);
                                is_new) {
                                SPDLOG_LOGGER_INFO(
                                  LOGGER,
                                  "New source added to peer session for subscribe fullname: {} source_node: {} is "
                                  "via peer_session_id: {} sns_id: {}",
                                  sub_info.details.track_hash.track_fullname_hash,
                                  sub_info.track.source_node_id,
                                  peer_session->GetSessionId(),
                                  sns_id);

                                if (auto [_, is_new] = info_base_->client_fib_.try_emplace(
                                      { sub_info.details.track_hash.track_fullname_hash, peer_session->GetSessionId() },
                                      ForwardingBase::FibEntry{ update_ref, {}, sns_id, bp_it->second });
                                    is_new) {
                                    SPDLOG_LOGGER_INFO(LOGGER,
                                                       "New subscribe fullname: {} added to client fib",
                                                       sub_info.details.track_hash.track_fullname_hash);
                                }
                            }
                        }

                        if (auto* delegate = LoadDelegate()) {
                            SPDLOG_LOGGER_INFO(LOGGER,
                                               "Notifying delegate of subscribe fullname: {}",
                                               sub_info.details.track_hash.track_fullname_hash);
                            delegate->OnPeerSubscribe(ToTrackName(sub_info.track.name_space, sub_info.track.name),
                                                      sub_info.details.track_hash.track_fullname_hash,
                                                      ToParams(sub_info));
                        }
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------
    // Peer Manager
    // -------------------------------------------------------------

    Engine::Engine(Config config)
      : info_base_(std::make_shared<ForwardingBase>())
      , config_(std::move(config))
    {
        if (!config_.logger) {
            const auto name = "moq-peering-" + config_.node_id;
            config_.logger = spdlog::get(name);
            if (!config_.logger) {
                config_.logger = spdlog::stdout_color_mt(name);
            }
        }
        SPDLOG_LOGGER_INFO(
          LOGGER, "Peering manager Node ID: {} listening port: {}", config_.node_id, config_.listen_port);

        check_thr_ = std::thread(&Engine::CheckThread, this, static_cast<int>(config_.check_interval_ms));

        node_info_.contact = config_.node_id;
        node_info_.id = std::hash<std::string>{}(config_.node_id);
        node_info_.type = config_.node_type;

        server_endpoint_ = QuicEndpoint::Listen(config_.tls_cert_filename,
                                                config_.tls_key_filename,
                                                config_.listen_port,
                                                [this](const auto& connection) { NewPeerConnection(connection); });

        for (const auto& [host, port] : config_.peers) {
            CreatePeerSession(host, port);
        }
    }

    void Engine::SetDelegate(Delegate* delegate)
    {
        delegate_.store(delegate, std::memory_order_release);
    }

    Engine::~Engine()
    {
        // Stop threads
        stop_ = true;

        SPDLOG_LOGGER_INFO(LOGGER, "Closing peer manager threads");

        if (check_thr_.joinable())
            check_thr_.join();

        // Callbacks keep a session alive and can run after the map releases it. Disconnect joins
        // outbound packet loops first, while this engine is still intact for those callbacks.
        std::vector<std::shared_ptr<PeerSession>> sessions;
        sessions.reserve(client_peer_sessions_.size() + server_peer_sessions_.size());
        for (const auto& [_, sess] : client_peer_sessions_) {
            sessions.push_back(sess);
        }
        for (const auto& [_, sess] : server_peer_sessions_) {
            sessions.push_back(sess);
        }
        for (const auto& sess : sessions) {
            sess->Disconnect();
        }

        client_peer_sessions_.clear();
        server_peer_sessions_.clear();
        sessions.clear();

        if (server_endpoint_ != nullptr) {
            server_endpoint_->Shutdown();
            server_endpoint_.reset();
        }

        SPDLOG_LOGGER_INFO(LOGGER, "Closed peer manager stopped");
    }

    void Engine::SnsReceived(PeerSession& peer_session, const SubscribeNodeSet& sns, bool withdraw)
    {
        uint64_t update_ref = rand();

        std::unique_lock engine_lock(mutex_);
        std::unique_lock ib_lock(info_base_->mutex_);

        if (withdraw) {
            auto it = info_base_->peer_fib_.find({ peer_session.GetSessionId(), sns.id });
            if (it != info_base_->peer_fib_.end()) {
                for (auto& [out_peer_sess_id, entry] : it->second) {
                    if (out_peer_sess_id == 0)
                        continue;

                    CloseFibStreams(entry);

                    auto out_peer_sess = entry.peer_session.lock();
                    out_peer_sess->RemovePeerSnsSourceNode(peer_session.GetSessionId(), sns.id, 0);
                }

                info_base_->peer_fib_.erase(it);
            }

            return;
        }

        auto [fib_it, new_ingress] = info_base_->peer_fib_.try_emplace({ peer_session.GetSessionId(), sns.id });
        if (new_ingress) {
            SPDLOG_LOGGER_DEBUG(
              LOGGER, "New ingress SNS peer session: {} sns id: {}", peer_session.GetSessionId(), sns.id);

            for (const auto& node_id : sns.nodes) {

                if (node_id == node_info_.id) {
                    // Self
                    fib_it->second[0] = ForwardingBase::FibEntry{ update_ref, {} };
                    continue;
                }

                auto peer_sess_weak = info_base_->GetBestPeerSession(node_id);
                if (auto peer_sess = peer_sess_weak.lock()) {

                    const auto [out_sns_id, out_new] =
                      peer_sess->AddPeerSnsSourceNode(peer_session.GetSessionId(), sns.id, node_id, sns.priority);

                    // Update or create fib record
                    fib_it->second[peer_sess->GetSessionId()] =
                      ForwardingBase::FibEntry{ update_ref, {}, out_sns_id, peer_sess_weak };
                }
            }
        }

        else { // Existing
            SPDLOG_LOGGER_DEBUG(
              LOGGER, "Update to ingress SNS peer session: {} sns id: {}", peer_session.GetSessionId(), sns.id);

            for (const auto& node_id : sns.nodes) {
                if (node_id == node_info_.id) {
                    // Self
                    fib_it->second[0] = ForwardingBase::FibEntry{ update_ref, {} };
                    continue;
                }

                auto peer_sess_weak = info_base_->GetBestPeerSession(node_id);

                if (auto peer_sess = peer_sess_weak.lock()) {
                    auto it = fib_it->second.find(peer_sess->GetSessionId());
                    if (it == fib_it->second.end()) {
                        // New entry
                        const auto [o_sns_id, __] =
                          peer_sess->AddPeerSnsSourceNode(peer_session.GetSessionId(), sns.id, node_id, sns.priority);

                        fib_it->second[peer_sess->GetSessionId()] =
                          ForwardingBase::FibEntry{ update_ref, {}, o_sns_id, peer_sess_weak };

                        SPDLOG_LOGGER_DEBUG(LOGGER,
                                            "SNS added peer session: {} sns id: {} added source node_id: {}",
                                            peer_sess->GetSessionId(),
                                            o_sns_id,
                                            NodeId().Value(node_id));

                    } else {
                        // Existing entry. Keep the egress streams already carrying this subgroup.
                        // Replacing the entry drops that map, and later objects are discarded until a new stream.
                        const auto [o_sns_id, is_new] =
                          peer_sess->AddPeerSnsSourceNode(peer_session.GetSessionId(), sns.id, node_id, sns.priority);
                        if (is_new) {
                            SPDLOG_LOGGER_DEBUG(LOGGER,
                                                "SNS update peer session: {} sns id: {} added source node_id: {}",
                                                it->second.peer_session.lock()->GetSessionId(),
                                                o_sns_id,
                                                NodeId().Value(node_id));
                        }

                        it->second.update_ref = update_ref;
                        it->second.out_sns_id = o_sns_id;
                        it->second.peer_session = peer_sess_weak;
                    }
                }
            }

            // Not ideal, but iterate over map of peers to remove entries that were not updated
            std::vector<PeerSessionId> remove_peers;
            for (auto& [peer_sess_id, entry] : fib_it->second) {
                if (entry.update_ref == update_ref)
                    continue;

                SPDLOG_LOGGER_DEBUG(
                  LOGGER, "SNS update remove peer session: {} sns id: {}", peer_sess_id, entry.out_sns_id);

                if (const auto peer_sess = entry.peer_session.lock()) {
                    peer_sess->RemovePeerSnsSourceNode(peer_sess->GetSessionId(), sns.id, 0);
                }

                remove_peers.push_back(peer_sess_id);
            }

            for (const auto& peer_sess_id : remove_peers) {
                fib_it->second.erase(peer_sess_id);
            }
        }

        // A datagram can pass the control stream. Replay anything that arrived before this SNS.
        // ForwardPeerData may wait on another connection's packet thread to open a stream, so both
        // locks have to be released first. Holding them across that wait stalls the other thread.
        auto pending = peer_session.TakePending(sns.id);
        ib_lock.unlock();
        engine_lock.unlock();

        for (auto& item : pending) {
            ForwardPeerData(peer_session.GetSessionId(),
                            item.is_new_stream,
                            item.stream_id,
                            item.header,
                            item.data,
                            item.data_offset,
                            item.flags);
        }
    }

    void Engine::ForwardingBaseSyncPeer(PeerSession& peer_session)
    {
        std::lock_guard _(mutex_);

        // Send all node info
        for (auto [key, node_item] : info_base_->nodes_) {
            if (key.first == peer_session.node_info_.id || key.second == peer_session.GetSessionId() ||
                key.first == peer_session.remote_node_info_.id)
                continue; // Skip, node is self, learned from peer, or peer is the node info

            bool skip{ false };
            for (auto& npi : node_item.node_info.path) {
                if (npi.id == peer_session.remote_node_info_.id) {
                    skip = true;
                    break; // Skip, remote peer is in path
                }
            }

            if (skip)
                continue;

            node_item.node_info.path.push_back({ peer_session.node_info_.id, peer_session.metrics_.srtt_us });
            peer_session.SendNodeInfo(node_item.node_info);
        }

        for (const auto& [th, anno_item] : info_base_->announces_) {
            for (const auto& [_, anno_info] : anno_item) {
                if (peer_session.remote_node_info_.id == anno_info.track.source_node_id)
                    continue; // Skip, don't send self or remote to self

                peer_session.SendAnnounceInfo(anno_info);
            }
        }

        // Send all subscribes
        for (auto& [tfh, sub_item] : info_base_->subscribes_) {
            for (auto& [_, sub_info] : sub_item) {
                if (peer_session.remote_node_info_.id == sub_info.track.source_node_id)
                    continue; // Skip, don't send self or remote to self

                peer_session.SendSubscribeInfo(sub_info);
            }
        }
    }

    void Engine::PropagateNodeInfo(PeerSessionId peer_session_id, const NodeInfo& node_info, bool withdraw)
    {
        std::lock_guard _(mutex_);

        auto server_it = server_peer_sessions_.find(peer_session_id);
        if (server_it != server_peer_sessions_.end()) {
            if (server_it->second->remote_node_info_.id != node_info.id)
                server_it->second->SendNodeInfo(node_info, withdraw);
            return;
        }

        auto client_it = client_peer_sessions_.find(peer_session_id);
        if (client_it != client_peer_sessions_.end()) {
            if (client_it->second->remote_node_info_.id != node_info.id)
                client_it->second->SendNodeInfo(node_info, withdraw);
            return;
        }
    }

    void Engine::PropagateNodeInfo(const NodeInfo& node_info, bool withdraw)
    {
        auto skip_node = [](const NodeInfo& node_a, const NodeInfo& node_b) -> bool {
            if (node_a.id == node_b.id || node_b.id == 0 || node_a.id == 0)
                return true;

            for (auto& npi : node_a.path) {
                if (npi.id == node_b.id) {
                    return true;
                }
            }

            return false;
        };

        std::lock_guard _(mutex_);

        // Advertise node info to peer
        for (auto& [_, peer_session] : client_peer_sessions_) {
            if (skip_node(node_info, peer_session->remote_node_info_))
                continue;

            peer_session->SendNodeInfo(node_info, withdraw);

            SPDLOG_LOGGER_DEBUG(LOGGER,
                                "Sending node info; id: {} contact: {} --> remote id: {} contact: {} withdraw: {}",
                                node_info.id,
                                node_info.contact,
                                peer_session->remote_node_info_.id,
                                peer_session->remote_node_info_.contact,
                                withdraw);
        }

        for (auto& [_, peer_session] : server_peer_sessions_) {
            if (skip_node(node_info, peer_session->remote_node_info_))
                continue;

            peer_session->SendNodeInfo(node_info, withdraw);

            SPDLOG_LOGGER_DEBUG(LOGGER,
                                "Sending node info; id: {} contact: {} --> remote id: {} --> contact: {} withdraw: {}",
                                node_info.id,
                                node_info.contact,
                                peer_session->remote_node_info_.id,
                                peer_session->remote_node_info_.contact,
                                withdraw);
        }
    }

    inline std::shared_ptr<PeerSession> Engine::GetPeerSession(const PeerSessionId peer_session_id)
    {
        auto s_peer_it = server_peer_sessions_.find(peer_session_id);
        if (s_peer_it != server_peer_sessions_.end()) {
            return s_peer_it->second;
        }

        auto c_peer_it = client_peer_sessions_.find(peer_session_id);
        if (c_peer_it != client_peer_sessions_.end()) {
            return c_peer_it->second;
        }

        throw std::invalid_argument("Peer session id does not exist");
    }

    void Engine::CreatePeerSession(const std::string& host, uint16_t port)
    {
        auto peer_sess = std::make_shared<PeerSession>(false, config_, node_info_, host, port, *this);
        peer_sess->Connect();
        if (peer_sess->GetSessionId() == 0) {
            return;
        }

        client_peer_sessions_.try_emplace(peer_sess->GetSessionId(), peer_sess);
        peer_sess->Begin();
    }

    void Engine::CheckThread(int interval_ms)
    {
        SPDLOG_LOGGER_INFO(LOGGER, "Running peer manager outbound peer connection thread");

        if (interval_ms < 2000)
            interval_ms = 2000;

        auto start = std::chrono::system_clock::now();

        while (not stop_) {
            auto check = std::chrono::system_clock::now();

            // Run check only after interval ms
            if (std::chrono::duration_cast<std::chrono::milliseconds>(check - start).count() >= interval_ms) {
                start = std::chrono::system_clock::now();

                std::vector<std::shared_ptr<PeerSession>> reconnect;
                {
                    std::lock_guard lock(mutex_);
                    for (const auto& [_, sess] : client_peer_sessions_) {
                        if (sess && sess->Status() == PeerSession::StatusValue::kDisconnected) {
                            reconnect.push_back(sess);
                        }
                    }
                }

                struct Rekey
                {
                    PeerSessionId old_id{ 0 };
                    PeerSessionId new_id{ 0 };
                    std::shared_ptr<PeerSession> session;
                };
                std::vector<Rekey> rekey;
                for (const auto& sess : reconnect) {
                    const auto old_id = sess->GetSessionId();
                    // Reconnect replaces the endpoint, so the connection id changes.
                    SPDLOG_LOGGER_INFO(LOGGER, "Peer session {} disconnected, reconnecting", old_id);
                    sess->Connect();
                    const auto new_id = sess->GetSessionId();
                    if (new_id == 0) {
                        continue;
                    }
                    if (new_id != old_id) {
                        rekey.push_back(Rekey{ old_id, new_id, sess });
                    }
                    sess->Begin();
                }

                if (!rekey.empty()) {
                    std::lock_guard lock(mutex_);
                    for (const auto& item : rekey) {
                        const auto it = client_peer_sessions_.find(item.old_id);
                        if (it == client_peer_sessions_.end() || it->second != item.session) {
                            continue;
                        }
                        client_peer_sessions_.erase(it);
                        client_peer_sessions_.try_emplace(item.new_id, item.session);
                    }
                }
            }

            // Sleep shorter so that the loop can be stopped within this time instead of a larger interval
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms / 2));
        }
    }

    /*
     * Server transport callbacks
     */
    void Engine::NewPeerConnection(const std::shared_ptr<QuicConnection>& connection)
    {
        const auto conn_id = connection->Id();

        std::shared_ptr<PeerSession> peer_sess;

        {
            std::lock_guard _(mutex_);

            if (server_peer_sessions_.contains(conn_id)) {
                return;
            }

            SPDLOG_LOGGER_INFO(LOGGER, "New server accepted peer, conn_id: {0}", conn_id);

            const auto [ip, port] = connection->PeerAddress();

            peer_sess = std::make_shared<PeerSession>(true, config_, node_info_, ip, port, *this);
            peer_sess->SetConnection(connection);

            server_peer_sessions_.emplace(conn_id, peer_sess);
        }

        peer_sess->Attach(connection);
    }

    std::vector<PeerSnapshot> Engine::Peers()
    {
        std::vector<std::shared_ptr<PeerSession>> sessions;
        {
            std::lock_guard lock(mutex_);
            sessions.reserve(server_peer_sessions_.size() + client_peer_sessions_.size());
            for (const auto& [_, session] : server_peer_sessions_) {
                if (session) {
                    sessions.push_back(session);
                }
            }
            for (const auto& [_, session] : client_peer_sessions_) {
                if (session) {
                    sessions.push_back(session);
                }
            }
        }

        // Count forwarding entries before Snapshot(). RttUs waits on the QUIC thread, which also
        // takes the forwarding lock.
        const auto forwarding = info_base_->ForwardingCountsBySession();

        std::vector<PeerSnapshot> peers;
        peers.reserve(sessions.size());
        for (const auto& session : sessions) {
            auto peer = session->Snapshot();
            if (const auto it = forwarding.find(peer.session_id); it != forwarding.end()) {
                peer.subscribe_tracks = it->second.subscribe_tracks;
                peer.publishes = it->second.publishes;
            }
            peers.push_back(std::move(peer));
        }
        return peers;
    }

    void Engine::PeerConnectionClosed(uint64_t session_id)
    {
        std::shared_ptr<PeerSession> peer_sess;

        {
            std::lock_guard _(mutex_);

            auto peer_it = server_peer_sessions_.find(session_id);
            if (peer_it == server_peer_sessions_.end()) {
                return;
            }

            peer_sess = std::move(peer_it->second);
            server_peer_sessions_.erase(peer_it);
        }

        SPDLOG_LOGGER_DEBUG(LOGGER, "Peer conn_id {0} closed", session_id);

        /*
         * The connection holds a weak reference to the session, so the session's own disconnect notification
         * is not guaranteed to be delivered before the session is dropped here. Report it only when the
         * session has not already seen the status change, to avoid withdrawing the peer's info twice.
         */
        if (peer_sess->Status() != PeerSession::StatusValue::kDisconnected) {
            SessionChanged(
              peer_sess->GetSessionId(), PeerSession::StatusValue::kDisconnected, peer_sess->remote_node_info_);
        }
    }

    void Engine::CloseFibStreams(ForwardingBase::FibEntry& entry)
    {
        const auto peer_sess = entry.peer_session.lock();
        if (peer_sess != nullptr) {
            for (const auto& [_, out_stream] : entry.streams) {
                peer_sess->FinishStream(out_stream);
            }
        }

        entry.streams.clear();
    }

    void Engine::CloseStream(PeerSessionId peer_session_id,
                             SubscribeNodeSetId sns,
                             uint64_t stream_id,
                             uint64_t track_fullname_hash,
                             StreamClose flag)
    {
        // Engine mutex first, then the forwarding tables. SnsReceived uses that same order.
        std::lock_guard engine_lock(mutex_);
        std::lock_guard ib_lock(info_base_->mutex_);

        // Close all egress peer streams related to the ingress stream close
        auto it = info_base_->peer_fib_.find({ peer_session_id, sns });
        if (it != info_base_->peer_fib_.end()) {
            for (auto& [out_peer_sess_id, entry] : it->second) {
                if (out_peer_sess_id == 0) {
                    // Client manager
                    if (auto* delegate = LoadDelegate()) {
                        delegate->OnPeerStreamClosed(track_fullname_hash, stream_id, flag == StreamClose::kReset);
                    }

                    continue;
                }
                auto stream_it = entry.streams.find(IngressStreamKey(stream_id));
                if (stream_it != entry.streams.end()) {
                    if (auto out_peer_sess = entry.peer_session.lock()) {
                        out_peer_sess->CloseStream(stream_it->second, flag);
                        entry.streams.erase(stream_it);
                    }
                }
            }
        }
    }

} // namespace moq::peering
