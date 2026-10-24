// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <moq/peering/peer_manager.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace moq::peering::examples {

    enum class ExampleKind
    {
        kRelay,
        kProducer,
        kSubscriber,
    };

    struct CommonOptions
    {
        std::string node_id;
        NodeType node_type{ NodeType::kEdge };
        uint16_t listen_port{ 0 };
        std::vector<std::pair<std::string, uint16_t>> peers;
        std::string cert;
        std::string key;
        bool help{ false };
    };

    struct ExampleOptions
    {
        CommonOptions common;
        std::string name_space{ "demo" };
        std::string track{ "object" };
        int interval_ms{ 1000 };
        std::string payload{ "hello" };
    };

    ExampleOptions ParseArgs(ExampleKind kind, int argc, char** argv);
    std::string HelpText(ExampleKind kind);

    /// Read the certificate file and reject an expired, not-yet-valid, weak, or SHA-1/MD5 certificate.
    /// A self-signed certificate is allowed for these development examples and is reported on stderr.
    /// The private key is checked against the certificate and is not printed.
    void CheckCertificate(const std::string& cert_path, const std::string& key_path);

    std::shared_ptr<spdlog::logger> MakeLogger(const std::string& node_id);
    Config MakeConfig(const CommonOptions& options, const std::shared_ptr<spdlog::logger>& logger);

    TrackName MakeTrack(const std::string& name_space, const std::string& track);
    std::string FormatTrack(const TrackName& name);

    void WaitForInterrupt();

} // namespace moq::peering::examples
