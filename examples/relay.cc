// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// A relay that forwards peering announces, subscribes, and objects.
// --type selects edge, via, or stub. This process does not publish or subscribe.

#include "example_util.h"

#include <iostream>
#include <stdexcept>

namespace {

    const char* TypeName(moq::peering::NodeType type)
    {
        switch (type) {
            case moq::peering::NodeType::kVia:
                return "via";
            case moq::peering::NodeType::kEdge:
                return "edge";
            case moq::peering::NodeType::kStub:
                return "stub";
        }
        return "edge";
    }

    class RelayApp : public moq::peering::Delegate
    {
      public:
        explicit RelayApp(std::shared_ptr<spdlog::logger> logger)
          : logger_(std::move(logger))
        {
        }

        void OnPeerUp(std::uint64_t session_id) override { logger_->info("peer up session {}", session_id); }

        void OnPeerDown(std::uint64_t session_id) override { logger_->info("peer down session {}", session_id); }

        void OnPeerTrack(const moq::peering::TrackName& name, bool withdrawn) override
        {
            logger_->info(
              "track {} {}", withdrawn ? "withdrawn" : "announced", moq::peering::examples::FormatTrack(name));
        }

        void OnPeerNamespace(const std::vector<std::vector<uint8_t>>& name_space, bool withdrawn) override
        {
            moq::peering::TrackName name;
            name.name_space = name_space;
            logger_->info(
              "namespace {} {}", withdrawn ? "withdrawn" : "announced", moq::peering::examples::FormatTrack(name));
        }

        void OnPeerSubscribe(const moq::peering::TrackName& name,
                             std::uint64_t track_hash,
                             const moq::peering::SubscribeParams&) override
        {
            logger_->info("subscribe {} hash {}", moq::peering::examples::FormatTrack(name), track_hash);
        }

        void OnPeerUnsubscribe(std::uint64_t track_hash, bool subscribers_remain) override
        {
            logger_->info("unsubscribe hash {} subscribers_remain {}", track_hash, subscribers_remain);
        }

      private:
        std::shared_ptr<spdlog::logger> logger_;
    };

} // namespace

int
main(int argc, char** argv)
{
    using moq::peering::examples::ExampleKind;

    try {
        const auto options = moq::peering::examples::ParseArgs(ExampleKind::kRelay, argc, argv);
        if (options.common.help) {
            std::cout << moq::peering::examples::HelpText(ExampleKind::kRelay);
            return 0;
        }

        moq::peering::examples::CheckCertificate(options.common.cert, options.common.key);
        auto logger = moq::peering::examples::MakeLogger(options.common.node_id);
        RelayApp app(logger);

        moq::peering::PeerManager peers(moq::peering::examples::MakeConfig(options.common, logger));
        peers.SetDelegate(&app);
        logger->info("relay {} type {} listening on {}",
                     options.common.node_id,
                     TypeName(options.common.node_type),
                     options.common.listen_port);
        for (const auto& [host, port] : options.common.peers) {
            logger->info("dialing {}:{}", host, port);
        }

        moq::peering::examples::WaitForInterrupt();
        logger->info("stopping");
        peers.SetDelegate(nullptr);
        spdlog::drop(logger->name());
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        std::cerr << moq::peering::examples::HelpText(ExampleKind::kRelay);
        return 1;
    }
    return 0;
}
