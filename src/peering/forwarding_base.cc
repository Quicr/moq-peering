// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include "forwarding_base.h"
#include "name.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <utility>

namespace moq::peering {
    namespace {
        bool SameAdvertisement(const NodeInfo& left, const NodeInfo& right)
        {
            if (left.metric != right.metric || left.type != right.type || left.contact != right.contact ||
                left.longitude != right.longitude || left.latitude != right.latitude ||
                left.path.size() != right.path.size()) {
                return false;
            }

            for (std::size_t i = 0; i < left.path.size(); ++i) {
                if (left.path[i].id != right.path[i].id || left.path[i].srtt_us != right.path[i].srtt_us ||
                    left.path[i].metric != right.path[i].metric) {
                    return false;
                }
            }
            return true;
        }

        /// Received path sum, plus the extra cost of egressing on a session whose metric is above the node metric.
        uint64_t SelectionCost(const NodeInfo& info, const std::shared_ptr<PeerSession>& session)
        {
            auto cost = info.SumMetric();
            if (!session) {
                return cost;
            }
            const auto advertised = session->AdvertisedMetric();
            const auto base = session->node_info_.metric;
            if (advertised > base) {
                cost += advertised - base;
            }
            return cost;
        }

        /// Distance 1..32767 through a 16-bit ring. Zero is newer than 65535.
        bool SequenceIsNewer(std::uint16_t received, std::uint16_t stored)
        {
            const auto distance = static_cast<std::uint16_t>(received - stored);
            return distance >= 1 && distance <= 32767;
        }
    } // namespace

    ForwardingBase::NodeAddResult ForwardingBase::AddNode(std::shared_ptr<PeerSession> peer_session,
                                                          const NodeInfo& node_info)
    {
        std::lock_guard _(mutex_);

        NodeInfo previous;
        bool had_previous{ false };
        auto it = nodes_.find({ node_info.id, peer_session->GetSessionId() });
        if (it == nodes_.end()) {
            // New node entry
            nodes_.try_emplace({ node_info.id, peer_session->GetSessionId() }, NodeItem{ peer_session, node_info });
        } else {
            had_previous = true;
            previous = it->second.node_info;
            it->second = { peer_session, node_info };
        }

        nodes_by_peer_session_[peer_session->GetSessionId()].emplace(node_info.id);

        NodeAddResult result;
        result.best_changed = SelectBestNode(node_info.id);

        const auto best = nodes_best_.find(node_info.id);
        if (best != nodes_best_.end()) {
            if (const auto session = best->second.lock(); session && session == peer_session) {
                result.best_info_changed = !had_previous || !SameAdvertisement(previous, node_info);
            }
        }
        NoteSourceReachableUnlocked(node_info.id);
        return result;
    }

    bool ForwardingBase::RemoveNode(PeerSessionId peer_session_id, NodeIdValueType node_id)
    {
        std::lock_guard _(mutex_);

        auto ids_it = nodes_by_peer_session_.find(peer_session_id);
        if (ids_it != nodes_by_peer_session_.end()) {
            ids_it->second.erase(node_id);

            if (ids_it->second.empty()) {
                nodes_by_peer_session_.erase(ids_it);
            }
        }

        nodes_.erase({ node_id, peer_session_id });

        if (nodes_best_.erase(node_id) > 0) {
            SelectBestNode(node_id);
            // TODO(tievens): Update subscribes and announces based on best change
        }

        bool still_reachable{ false };
        for (const auto& entry : nodes_) {
            if (entry.first.first == node_id) {
                still_reachable = true;
                break;
            }
        }
        if (!still_reachable) {
            NoteSourceUnreachableUnlocked(node_id, std::chrono::steady_clock::now());
        }
        return still_reachable;
    }

    ForwardingBase::SessionPurge ForwardingBase::PurgePeerSessionInfo(PeerSessionId peer_session_id)
    {
        SessionPurge result;
        std::lock_guard _(mutex_);

        auto ids_it = nodes_by_peer_session_.find(peer_session_id);
        if (ids_it != nodes_by_peer_session_.end()) {
            for (const auto& node_id : ids_it->second) {
                NodeInfo withdrawn;
                bool have_info{ false };
                if (const auto node_it = nodes_.find({ node_id, peer_session_id }); node_it != nodes_.end()) {
                    withdrawn = node_it->second.node_info;
                    have_info = true;
                }

                nodes_.erase({ node_id, peer_session_id });

                if (nodes_best_.erase(node_id) > 0) {
                    SelectBestNode(node_id);
                }

                bool still_reachable{ false };
                for (const auto& entry : nodes_) {
                    if (entry.first.first == node_id) {
                        still_reachable = true;
                        break;
                    }
                }
                if (!still_reachable) {
                    result.gone.push_back(node_id);
                    if (have_info) {
                        result.nodes.push_back(std::move(withdrawn));
                    }
                    NoteSourceUnreachableUnlocked(node_id, std::chrono::steady_clock::now());
                }
            }

            nodes_by_peer_session_.erase(ids_it);
        }

        for (auto it = client_fib_.begin(); it != client_fib_.end();) {
            if (it->first.second == peer_session_id) {
                it = client_fib_.erase(it);
            } else {
                ++it;
            }
        }

        for (auto it = peer_fib_.begin(); it != peer_fib_.end();) {
            auto& egress = it->second;
            if (it->first.first == peer_session_id) {
                it = peer_fib_.erase(it);
                continue;
            }

            for (auto egress_it = egress.begin(); egress_it != egress.end();) {
                if (egress_it->first == peer_session_id) {
                    egress_it = egress.erase(egress_it);
                } else {
                    ++egress_it;
                }
            }

            if (egress.empty()) {
                it = peer_fib_.erase(it);
            } else {
                ++it;
            }
        }

        return result;
    }

    bool ForwardingBase::HasSubscribers(const SubscribeInfo& subscribe_info)
    {
        auto it = subscribes_.find(subscribe_info.track.fullname_hash);
        if (it != subscribes_.end()) {
            for (const auto& si : it->second) {
                if (si.second.track.source_node_id != subscribe_info.track.source_node_id) {
                    return true;
                }
            }
        }

        return false;
    }

    bool ForwardingBase::AddSubscribe(const SubscribeInfo& subscribe_info)
    {
        std::lock_guard _(mutex_);
        ExpireSubscribeSequencesUnlocked(std::chrono::steady_clock::now());

        const auto hash = subscribe_info.track.fullname_hash;
        const auto source = subscribe_info.track.source_node_id;
        const auto incoming_epoch = subscribe_info.details.epoch;
        const auto incoming = subscribe_info.details.seq;
        const auto key = std::make_pair(hash, source);

        SubscribeInfo* existing = nullptr;
        if (const auto track = subscribes_.find(hash); track != subscribes_.end()) {
            if (const auto it = track->second.find(source); it != track->second.end()) {
                existing = &it->second;
            }
        }

        if (const auto mark = subscribe_seq_.find(key); mark != subscribe_seq_.end()) {
            // A different epoch is a reset. Sequence distance does not apply, and accepting it
            // would cancel retention. 0 is greater than 65535 only inside the same epoch.
            if (incoming_epoch != mark->second.epoch) {
                return false;
            }
            const bool same = incoming == mark->second.seq;
            // The source left and came back with the same counter. A withdrawal has already
            // moved the stored sequence ahead of the old advertisement, so this cannot restore it.
            const bool resume = same && !mark->second.withdrawn && existing == nullptr;
            if (!SequenceIsNewer(incoming, mark->second.seq) && !resume) {
                return false;
            }
        }

        if (existing != nullptr) {
            *existing = subscribe_info;
        } else {
            subscribes_[hash].emplace(source, subscribe_info);
        }

        auto& record = subscribe_seq_[key];
        record.epoch = incoming_epoch;
        record.seq = incoming;
        record.withdrawn = false;
        record.discard_at.reset();
        return true;
    }

    bool ForwardingBase::RemoveSubscribe(const SubscribeInfo& subscribe_info, bool force)
    {
        std::lock_guard _(mutex_);

        const auto hash = subscribe_info.track.fullname_hash;
        const auto source = subscribe_info.track.source_node_id;
        const auto incoming_epoch = subscribe_info.details.epoch;
        const auto incoming = subscribe_info.details.seq;
        const auto key = std::make_pair(hash, source);

        auto it = subscribes_.find(hash);
        if (it == subscribes_.end()) {
            return false;
        }

        auto sub_it = it->second.find(source);
        if (sub_it == it->second.end()) {
            return false;
        }

        auto stored_epoch = sub_it->second.details.epoch;
        auto stored = sub_it->second.details.seq;
        std::optional<std::chrono::steady_clock::time_point> discard_at;
        if (const auto mark = subscribe_seq_.find(key); mark != subscribe_seq_.end()) {
            stored_epoch = mark->second.epoch;
            stored = mark->second.seq;
            discard_at = mark->second.discard_at;
        }

        const bool same_epoch = incoming_epoch == stored_epoch;
        const bool newer = same_epoch && SequenceIsNewer(incoming, stored);
        if (!force && !newer) {
            return false;
        }

        it->second.erase(sub_it);
        if (it->second.empty()) {
            subscribes_.erase(it);
        }

        auto& record = subscribe_seq_[key];
        record.epoch = stored_epoch;
        record.seq = newer ? incoming : stored;
        // A source withdrawal moves the sequence forward inside the same epoch. Dropping the
        // entry because the source left the node table keeps the last advertisement resumable.
        record.withdrawn = !force;
        record.discard_at = discard_at;
        return true;
    }

    void ForwardingBase::SetLocalNode(NodeIdValueType node_id)
    {
        std::lock_guard _(mutex_);
        local_node_id_ = node_id;
    }

    void ForwardingBase::NoteSourceUnreachable(NodeIdValueType source, std::chrono::steady_clock::time_point now)
    {
        std::lock_guard _(mutex_);
        NoteSourceUnreachableUnlocked(source, now);
    }

    void ForwardingBase::NoteSourceReachable(NodeIdValueType source)
    {
        std::lock_guard _(mutex_);
        NoteSourceReachableUnlocked(source);
    }

    void ForwardingBase::ExpireSubscribeSequences(std::chrono::steady_clock::time_point now)
    {
        std::lock_guard _(mutex_);
        ExpireSubscribeSequencesUnlocked(now);
    }

    std::optional<std::uint16_t> ForwardingBase::StoredSequence(std::uint64_t track_fullname_hash,
                                                               NodeIdValueType source)
    {
        std::lock_guard _(mutex_);
        ExpireSubscribeSequencesUnlocked(std::chrono::steady_clock::now());
        const auto mark = subscribe_seq_.find({ track_fullname_hash, source });
        if (mark == subscribe_seq_.end()) {
            return std::nullopt;
        }
        return mark->second.seq;
    }

    std::optional<std::uint16_t> ForwardingBase::StoredEpoch(std::uint64_t track_fullname_hash, NodeIdValueType source)
    {
        std::lock_guard _(mutex_);
        ExpireSubscribeSequencesUnlocked(std::chrono::steady_clock::now());

        const auto mark = subscribe_seq_.find({ track_fullname_hash, source });
        if (mark == subscribe_seq_.end()) {
            return std::nullopt;
        }
        return mark->second.epoch;
    }

    void ForwardingBase::SeedSequence(std::uint64_t track_fullname_hash,
                                      NodeIdValueType source,
                                      std::uint16_t seq,
                                      std::uint16_t epoch)
    {
        std::lock_guard _(mutex_);
        auto& record = subscribe_seq_[{ track_fullname_hash, source }];
        record.epoch = epoch;
        record.seq = seq;
        record.withdrawn = false;
        record.discard_at.reset();
    }

    std::vector<SavedSubscribeSequence> ForwardingBase::SequencesFor(NodeIdValueType source)
    {
        std::lock_guard _(mutex_);
        ExpireSubscribeSequencesUnlocked(std::chrono::steady_clock::now());

        std::vector<SavedSubscribeSequence> rows;
        for (const auto& [key, record] : subscribe_seq_) {
            if (key.second == source) {
                rows.push_back(SavedSubscribeSequence{ key.first, record.epoch, record.seq });
            }
        }
        return rows;
    }

    void ForwardingBase::NoteSourceUnreachableUnlocked(NodeIdValueType source,
                                                       std::chrono::steady_clock::time_point now)
    {
        if (local_node_id_ != 0 && source == local_node_id_) {
            return;
        }

        const auto deadline = now + kSubscribeSeqRetention;
        for (const auto& [hash, by_source] : subscribes_) {
            const auto it = by_source.find(source);
            if (it == by_source.end()) {
                continue;
            }
            const auto key = std::make_pair(hash, source);
            const auto entry_epoch = it->second.details.epoch;
            const auto entry_seq = it->second.details.seq;
            const auto mark = subscribe_seq_.find(key);
            if (mark == subscribe_seq_.end()) {
                auto& record = subscribe_seq_[key];
                record.epoch = entry_epoch;
                record.seq = entry_seq;
            } else if (mark->second.epoch == entry_epoch && SequenceIsNewer(entry_seq, mark->second.seq)) {
                mark->second.seq = entry_seq;
            }
        }

        for (auto& [key, record] : subscribe_seq_) {
            if (key.second != source) {
                continue;
            }
            // A later observation of the same removal must not extend the interval.
            if (!record.discard_at || deadline < *record.discard_at) {
                record.discard_at = deadline;
            }
        }
    }

    void ForwardingBase::NoteSourceReachableUnlocked(NodeIdValueType /*source*/)
    {
        // A node advertisement means the source is reachable again. The retention interval
        // still ends 30 seconds after this receiver removed the source. Only a greater
        // subscribe sequence in the same epoch cancels it. A different epoch does not.
    }

    void ForwardingBase::ExpireSubscribeSequencesUnlocked(std::chrono::steady_clock::time_point now)
    {
        for (auto it = subscribe_seq_.begin(); it != subscribe_seq_.end();) {
            if (!it->second.discard_at || now < *it->second.discard_at) {
                ++it;
                continue;
            }

            const auto hash = it->first.first;
            const auto source = it->first.second;
            it = subscribe_seq_.erase(it);

            if (const auto track = subscribes_.find(hash); track != subscribes_.end()) {
                track->second.erase(source);
                if (track->second.empty()) {
                    subscribes_.erase(track);
                }
            }
        }
    }

    std::optional<SubscribeInfo> ForwardingBase::GetSubscribe(uint64_t track_fullname_hash, NodeIdValueType src_node_id)
    {
        std::lock_guard _(mutex_);

        auto it = subscribes_[track_fullname_hash].find(src_node_id);
        if (it != subscribes_[track_fullname_hash].end()) {
            return it->second;
        }

        return std::nullopt;
    }

    std::vector<std::size_t> ForwardingBase::PrefixHashNamespaceTuples(const NameSpace& name_space)
    {
        const auto& entries = name_space.GetHashes();
        std::vector<std::size_t> hashes(entries.size());

        uint64_t hash = 0;
        for (std::size_t i = 0; i < hashes.size(); ++i) {
            hash_combine(hash, entries[i]);
            hashes[i] = hash;
        }

        return hashes;
    }

    bool ForwardingBase::AddAnnounce(const AnnounceInfo& announce_info)
    {
        std::lock_guard _(mutex_);

        auto [__, is_new] =
          announces_[announce_info.track.fullname_hash].emplace(announce_info.track.source_node_id, announce_info);

        if (is_new) {
            for (const auto& prefix_hash : PrefixHashNamespaceTuples(announce_info.track.name_space)) {
                auto it = prefix_lookup_announces_.find(prefix_hash);
                if (it == prefix_lookup_announces_.end()) {
                    prefix_lookup_announces_.emplace(prefix_hash, std::set{ announce_info.track.fullname_hash });
                } else {
                    auto& hash_set = it->second;
                    if (auto s_it = hash_set.find(announce_info.track.fullname_hash); s_it == hash_set.end()) {
                        hash_set.emplace(announce_info.track.fullname_hash);
                    }
                }
            }
        }
        // TODO: If not new, update metrics in existing entry

        return is_new;
    }

    bool ForwardingBase::RemoveAnnounce(const AnnounceInfo& announce_info)
    {
        bool removed{ false };
        std::lock_guard _(mutex_);

        auto anno_it = announces_.find(announce_info.track.fullname_hash);
        if (anno_it != announces_.end()) {
            std::vector<uint64_t> remove_prefix_hashes;

            for (const auto& prefix_hash : PrefixHashNamespaceTuples(announce_info.track.name_space)) {
                const auto prefix_lookup_it = prefix_lookup_announces_.find(prefix_hash);
                if (prefix_lookup_it == prefix_lookup_announces_.end()) {
                    continue;
                }

                // remove announce full hash name from each prefix tuple set
                if (auto s_it = prefix_lookup_it->second.find(announce_info.track.fullname_hash);
                    s_it != prefix_lookup_it->second.end()) {
                    prefix_lookup_it->second.erase(s_it);
                    removed = true;

                    if (prefix_lookup_it->second.empty()) {
                        remove_prefix_hashes.push_back(prefix_hash);
                    }
                }
            }

            // clean up the prefix lookup announces map
            for (const auto prefix_hash : remove_prefix_hashes) {
                prefix_lookup_announces_.erase(prefix_hash);
            }

            if (anno_it->second.erase(announce_info.track.source_node_id) > 0) {
                removed = true;
            }

            if (anno_it->second.empty()) {
                announces_.erase(anno_it);
            }
        }

        return removed;
    }

    std::set<NodeIdValueType> ForwardingBase::GetAnnounceIds(NameSpace name_space,
                                                             std::vector<uint8_t> name,
                                                             bool exact)
    {
        std::set<NodeIdValueType> announces_ids;
        std::lock_guard _(mutex_);

        // Attempt to get a full match on namespace and/or namespace + name
        const auto th = TrackHash(name_space, name);
        auto it = announces_.find(th.track_fullname_hash);
        if (it != announces_.end()) {
            for (const auto& a_info : it->second) {
                announces_ids.emplace(a_info.first);
            }
        }

        if (!announces_ids.empty() || exact)
            return announces_ids;

        // prefix match
        const auto prefix_hashes = PrefixHashNamespaceTuples(name_space);

        auto p_it = prefix_lookup_announces_.find(prefix_hashes.back());
        if (p_it != prefix_lookup_announces_.end()) {
            for (auto f_hash : p_it->second) {
                auto it = announces_.find(f_hash);
                if (it != announces_.end()) {
                    for (const auto& [nid, ai] : it->second) {
                        announces_ids.emplace(nid);
                    }
                }
            }
        }

        return announces_ids;
    }

    std::weak_ptr<PeerSession> ForwardingBase::GetBestPeerSession(NodeIdValueType node_id)
    {
        std::lock_guard _(mutex_);

        auto it = nodes_best_.find(node_id);
        if (it != nodes_best_.end()) {
            return it->second;
        }
        return {};
    }

    bool ForwardingBase::SelectBestNode(NodeIdValueType node_id)
    {
        bool is_updated{ false };

        std::weak_ptr<PeerSession> best_peer_session;
        bool have_best{ false };
        NodeInfo best_node_info;

        auto best_it = nodes_best_.find(node_id);
        if (best_it != nodes_best_.end()) {
            if (const auto current = best_it->second.lock()) {
                const auto item = nodes_.find({ node_id, current->GetSessionId() });
                if (item != nodes_.end()) {
                    best_peer_session = current;
                    best_node_info = item->second.node_info;
                    have_best = true;
                }
            }
        }

        for (auto it = nodes_.lower_bound({ node_id, 0 }); it != nodes_.end(); it++) {
            auto& [key, node_item] = *it;

            if (key.first != node_id) {
                break;
            }

            const auto candidate = node_item.peer_session.lock();
            if (!candidate) {
                continue;
            }

            if (!have_best) {
                is_updated = true;
                best_peer_session = candidate;
                best_node_info = node_item.node_info;
                have_best = true;
                continue;
            }

            /**
             * Algorithm to select best peering session
             * TODO(tievens): Add more advance selectors, such as load, geo distance, ...
             *
             * Choose the node that first matches the below in the order defined:
             *
             * 1. Prefer the lower sum of metrics. The sum is the node metric plus each hop,
             *    plus any extra metric configured on the peering session used as the next hop.
             * 2. When the metric sums are equal, prefer fewer hops.
             * 3. When the hop counts are equal, prefer the lower total sRTT.
             *
             * Equal metric, hop count, and sRTT keep the peer already selected, so a repeated
             * advertisement does not move streams.
             */
            const auto candidate_metric = SelectionCost(node_item.node_info, candidate);
            const auto best_metric = SelectionCost(best_node_info, best_peer_session.lock());
            const auto candidate_hops = node_item.node_info.path.size();
            const auto best_hops = best_node_info.path.size();
            const bool lower_metric = candidate_metric < best_metric;
            const bool same_metric_fewer_hops = candidate_metric == best_metric && candidate_hops < best_hops;
            const bool same_metric_hops_lower_rtt = candidate_metric == best_metric && candidate_hops == best_hops &&
                                                    node_item.node_info.SumSrtt() < best_node_info.SumSrtt();
            if (lower_metric || same_metric_fewer_hops || same_metric_hops_lower_rtt) {
                is_updated = true;
                best_peer_session = candidate;
                best_node_info = node_item.node_info;
            }
        }

        if (is_updated) {
            nodes_best_[node_id] = best_peer_session;

            SPDLOG_DEBUG("Forwarding Table Dump BEGIN ------------------------------");

            // A removed peer drops its QUIC connection before this runs, so its session id is
            // already 0 and no longer matches the table key. Skip those rows. nodes_.at() would
            // throw and skip moving subscribers onto the path that remains.
            for (const auto& node : nodes_best_) {
                const auto session = node.second.lock();
                if (!session) {
                    continue;
                }
                const auto node_item = nodes_.find({ node.first, session->GetSessionId() });
                if (node_item == nodes_.end()) {
                    continue;
                }
                SPDLOG_DEBUG("Forwarding table node id: {} contact {} best via peer_session id: {} contact: {} "
                             "path_len: {} sum_metric: {} sum_srtt: {}",
                             NodeId().Value(node.first),
                             node_item->second.node_info.contact,
                             session->GetSessionId(),
                             session->remote_node_info_.contact,
                             node_item->second.node_info.path.size(),
                             node_item->second.node_info.SumMetric(),
                             node_item->second.node_info.SumSrtt());
            }
            SPDLOG_DEBUG("Forwarding Table Dump DONE ------------------------------");
        }

        return is_updated;
    }

    std::map<PeerSessionId, ForwardingBase::SessionForwardingCounts> ForwardingBase::ForwardingCountsBySession() const
    {
        std::lock_guard _(mutex_);

        std::map<PeerSessionId, SessionForwardingCounts> counts;

        // Local publishes sent to a peer to satisfy a subscribe. One entry is one track.
        for (const auto& entry : client_fib_) {
            const auto session_id = entry.first.second;
            if (session_id == 0) {
                continue;
            }
            counts[session_id].subscribe_tracks++;
            counts[session_id].active_streams += entry.second.streams.size();
        }

        // Objects received from a peer and sent on to another peer or to a local subscriber.
        for (const auto& entry : peer_fib_) {
            const auto& egress = entry.second;
            if (egress.empty()) {
                continue;
            }

            const auto ingress_id = entry.first.first;
            if (ingress_id != 0) {
                counts[ingress_id].publishes++;
            }

            for (const auto& egress_entry : egress) {
                const auto egress_id = egress_entry.first;
                if (egress_id == 0) {
                    continue;
                }
                counts[egress_id].subscribe_tracks++;
                counts[egress_id].active_streams += egress_entry.second.streams.size();
            }
        }

        return counts;
    }

    bool SaveSubscribeSequenceFile(const std::filesystem::path& path, const std::vector<SavedSubscribeSequence>& rows)
    {
        std::error_code ec;
        if (const auto parent = path.parent_path(); !parent.empty()) {
            std::filesystem::create_directories(parent, ec);
        }

        const auto temporary = std::filesystem::path(path.string() + ".tmp");
        {
            std::ofstream out(temporary, std::ios::trunc);
            if (!out) {
                return false;
            }

            const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
            out << "2 " << now << '\n';
            for (const auto& row : rows) {
                out << row.track_hash << ' ' << row.epoch << ' ' << row.seq << '\n';
            }
            out.close();
            if (!out) {
                std::filesystem::remove(temporary, ec);
                return false;
            }
        }

        std::filesystem::rename(temporary, path, ec);
        if (ec) {
            std::filesystem::remove(temporary, ec);
            return false;
        }
        return true;
    }

    std::vector<SavedSubscribeSequence> LoadSubscribeSequenceFile(const std::filesystem::path& path)
    {
        std::ifstream in(path);
        if (!in) {
            return {};
        }

        int version = 0;
        long long stamp = 0;
        in >> version >> stamp;
        if (!in || (version != 1 && version != 2) || stamp <= 0) {
            return {};
        }
        // The saved counter is still the last epoch and sequence this source sent, however old the file is.
        // A source that has the number continues from it. Version 1 has no epoch and continues at epoch 0.

        std::vector<SavedSubscribeSequence> rows;
        std::uint64_t hash = 0;
        unsigned int epoch = 0;
        unsigned int seq = 0;
        if (version == 1) {
            while (in >> hash >> seq) {
                if (seq > 65535) {
                    continue;
                }
                rows.push_back(SavedSubscribeSequence{ hash, 0, static_cast<std::uint16_t>(seq) });
            }
            return rows;
        }

        while (in >> hash >> epoch >> seq) {
            if (epoch > 65535 || seq > 65535) {
                continue;
            }
            rows.push_back(
              SavedSubscribeSequence{ hash, static_cast<std::uint16_t>(epoch), static_cast<std::uint16_t>(seq) });
        }
        return rows;
    }
}
