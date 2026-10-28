// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include <moq/peering/peer_manager.h>

#include "peering/engine.h"
#include "peering/messages/node_info.h"
#include "peering/name.h"

namespace moq::peering {
    std::string FormatNodeId(std::uint64_t id)
    {
        return NodeId().Value(id);
    }

    struct PeerManager::Impl
    {
        explicit Impl(Config config)
          : engine(std::move(config))
        {
        }

        Engine engine;
    };

    PeerManager::PeerManager(const Config& config)
      : impl_(std::make_unique<Impl>(config))
    {
    }

    PeerManager::~PeerManager() = default;

    void PeerManager::SetDelegate(Delegate* delegate)
    {
        impl_->engine.SetDelegate(delegate);
    }

    void PeerManager::Announce(const TrackName& name, Announcement kind, bool withdraw)
    {
        impl_->engine.Announce(name, kind, withdraw);
    }

    void PeerManager::Subscribe(const TrackName& name, const SubscribeParams& params)
    {
        impl_->engine.Subscribe(name, params);
    }

    void PeerManager::UpdateSubscribe(const TrackName& name, const SubscribeParams& params)
    {
        impl_->engine.UpdateSubscribe(name, params);
    }

    void PeerManager::Unsubscribe(std::uint64_t track_hash)
    {
        impl_->engine.Unsubscribe(track_hash);
    }

    bool PeerManager::HasSubscribers(std::uint64_t track_hash) const
    {
        return impl_->engine.HasSubscribers(track_hash);
    }

    std::vector<PeerSnapshot> PeerManager::Peers()
    {
        return impl_->engine.Peers();
    }

    std::uint64_t PeerManager::LocalNodeId() const
    {
        return impl_->engine.LocalNodeId();
    }

    PeerAdminResult PeerManager::AddPeer(const std::string& host, std::uint16_t port)
    {
        return impl_->engine.AddPeer(host, port);
    }

    PeerAdminResult PeerManager::RemovePeer(const std::string& host, std::uint16_t port)
    {
        return impl_->engine.RemovePeer(host, port);
    }

    PeerAdminResult PeerManager::RestartPeer(const std::string& host, std::uint16_t port)
    {
        return impl_->engine.RestartPeer(host, port);
    }

    void PeerManager::SendData(std::uint64_t track_hash,
                               uint8_t priority,
                               uint32_t ttl_ms,
                               DataType type,
                               uint64_t group_id,
                               uint64_t subgroup_id,
                               std::shared_ptr<const std::vector<uint8_t>> data)
    {
        impl_->engine.SendData(track_hash, priority, ttl_ms, type, group_id, subgroup_id, std::move(data));
    }

    void PeerManager::EndSubgroup(std::uint64_t track_hash, uint64_t group_id, uint64_t subgroup_id, bool reset)
    {
        impl_->engine.EndSubgroup(track_hash, group_id, subgroup_id, reset);
    }

    std::uint64_t PeerManager::HashTrack(const TrackName& name)
    {
        return TrackHash(name).track_fullname_hash;
    }

} // namespace moq::peering
