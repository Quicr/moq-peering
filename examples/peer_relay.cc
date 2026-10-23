// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Two relays exchange one object with the peering API. This example does not open a MoQ session.
//
// The QUIC transport still needs a certificate and key on disk. Pass paths to files you have
// already checked (expiry, key size, signature algorithm). Do not embed certificate material here.
//
//   peer_relay <cert> <key>

#include <moq/peering/peer_manager.h>

#include <spdlog/sinks/stdout_color_sinks.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

    using namespace moq::peering;

    TrackName DemoTrack()
    {
        TrackName name;
        const std::string name_space = "demo";
        const std::string track = "object";
        name.name_space.push_back({ name_space.begin(), name_space.end() });
        name.name.assign(track.begin(), track.end());
        return name;
    }

    class Publisher : public Delegate
    {
      public:
        explicit Publisher(PeerManager& peers)
          : peers_(peers)
          , track_hash_(PeerManager::HashTrack(DemoTrack()))
        {
        }

        void OnPeerSubscribe(const TrackName&, std::uint64_t track_hash, const SubscribeParams&) override
        {
            if (track_hash != track_hash_) {
                return;
            }

            auto payload = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{ 'p', 'e', 'e', 'r' });
            peers_.SendData(track_hash, 10, 1000, DataType::kDatagram, 1, 0, std::move(payload));
            subscribed_.store(true);
        }

        bool subscribed() const { return subscribed_.load(); }

      private:
        PeerManager& peers_;
        std::uint64_t track_hash_;
        std::atomic<bool> subscribed_{ false };
    };

    class Subscriber : public Delegate
    {
      public:
        void OnPeerData(std::uint64_t,
                        bool,
                        std::optional<std::uint64_t>,
                        std::shared_ptr<const std::vector<uint8_t>> data) override
        {
            {
                std::lock_guard lock(mutex_);
                payload_.assign(data->begin(), data->end());
            }
            ready_.store(true);
            cv_.notify_one();
        }

        bool Wait(std::chrono::milliseconds timeout)
        {
            std::unique_lock lock(mutex_);
            return cv_.wait_for(lock, timeout, [&] { return ready_.load(); });
        }

        std::vector<uint8_t> payload() const
        {
            std::lock_guard lock(mutex_);
            return payload_;
        }

      private:
        mutable std::mutex mutex_;
        std::condition_variable cv_;
        std::vector<uint8_t> payload_;
        std::atomic<bool> ready_{ false };
    };

    Config MakeConfig(std::string node_id,
                      uint16_t listen_port,
                      std::vector<std::pair<std::string, uint16_t>> peers,
                      const std::string& cert,
                      const std::string& key)
    {
        Config config;
        config.node_id = std::move(node_id);
        config.node_type = NodeType::kEdge;
        config.listen_port = listen_port;
        config.peers = std::move(peers);
        config.tls_cert_filename = cert;
        config.tls_key_filename = key;
        config.logger = spdlog::stdout_color_mt("peer-" + config.node_id);
        config.logger->set_level(spdlog::level::info);
        return config;
    }

} // namespace

int
main(int argc, char** argv)
{
    if (argc != 3) {
        std::cerr << "usage: peer_relay <cert> <key>\n";
        return 2;
    }

    const std::string cert = argv[1];
    const std::string key = argv[2];
    if (!std::filesystem::exists(cert) || !std::filesystem::exists(key)) {
        std::cerr << "certificate or key file was not found\n";
        return 2;
    }
    const auto track = DemoTrack();

    auto publisher_config = MakeConfig("1:1", 33440, {}, cert, key);
    auto subscriber_config = MakeConfig("1:2", 33441, { { "127.0.0.1", 33440 } }, cert, key);

    try {
        PeerManager publisher_node(publisher_config);
        Publisher publisher(publisher_node);
        publisher_node.SetDelegate(&publisher);
        publisher_node.Announce(track, Announcement::kTrack);

        PeerManager subscriber_node(subscriber_config);
        Subscriber subscriber;
        subscriber_node.SetDelegate(&subscriber);

        SubscribeParams params;
        params.priority = 10;
        params.delivery_timeout_ms = 1000;
        params.forward = 1;
        subscriber_node.Subscribe(track, params);

        if (!subscriber.Wait(std::chrono::seconds(5))) {
            std::cerr << "timed out waiting for the peered object\n";
            publisher_node.SetDelegate(nullptr);
            subscriber_node.SetDelegate(nullptr);
            return 1;
        }

        const auto payload = subscriber.payload();
        std::cout << "received " << payload.size() << " bytes\n";

        publisher_node.SetDelegate(nullptr);
        subscriber_node.SetDelegate(nullptr);
        return payload == std::vector<uint8_t>{ 'p', 'e', 'e', 'r' } ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "peering example failed: " << ex.what() << '\n';
        return 1;
    }
}
