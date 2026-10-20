// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <moq/peering/types.h>

#include <memory>

namespace moq::peering {

    /**
     * @brief Relay-to-relay peering
     *
     * @details Owns QUIC sessions to other relays and the forwarding tables for names, subscribes, and
     *      objects. The application does not use a MoQ session. It calls the methods below to publish
     *      interest, and implements Delegate to learn what peers want.
     *
     *      Methods are safe to call from the application thread. Delegate methods run on peering threads.
     */
    class PeerManager
    {
      public:
        explicit PeerManager(const Config& config);
        ~PeerManager();

        PeerManager(const PeerManager&) = delete;
        PeerManager& operator=(const PeerManager&) = delete;

        /**
         * @brief Receive peering events
         *
         * @details Pass nullptr before the delegate is destroyed. The library does not own the delegate.
         */
        void SetDelegate(Delegate* delegate);

        /**
         * @brief Advertise or withdraw a track or namespace
         */
        void Announce(const TrackName& name, Announcement kind, bool withdraw = false);

        void Withdraw(const TrackName& name, Announcement kind) { Announce(name, kind, true); }

        void Subscribe(const TrackName& name, const SubscribeParams& params);
        void UpdateSubscribe(const TrackName& name, const SubscribeParams& params);
        void Unsubscribe(std::uint64_t track_hash);

        /// Full track-name hash used on the wire and by SendData, Unsubscribe, and HasSubscribers.
        static std::uint64_t HashTrack(const TrackName& name);

        /// True when at least one peer still wants objects for this track.
        bool HasSubscribers(std::uint64_t track_hash) const;

        /**
         * @brief Send one object to every peer subscribed to the track
         *
         * @param track_hash  Full track name hash. The same value passed to Subscribe callbacks.
         */
        void SendData(std::uint64_t track_hash,
                      uint8_t priority,
                      uint32_t ttl_ms,
                      DataType type,
                      uint64_t group_id,
                      uint64_t subgroup_id,
                      std::shared_ptr<const std::vector<uint8_t>> data);

        /**
         * @brief Finish a subgroup stream
         *
         * @param reset  True closes the stream with a reset. False finishes it after queued bytes.
         */
        void EndSubgroup(std::uint64_t track_hash, uint64_t group_id, uint64_t subgroup_id, bool reset = false);

      private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace moq::peering
