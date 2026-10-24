// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include "example_util.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <spdlog/sinks/stdout_color_sinks.h>

#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace moq::peering::examples {
    namespace {

        volatile std::sig_atomic_t g_stop = 0;

        void OnSignal(int)
        {
            g_stop = 1;
        }

        struct BioFree
        {
            void operator()(BIO* bio) const { BIO_free(bio); }
        };

        struct X509Free
        {
            void operator()(X509* cert) const { X509_free(cert); }
        };

        struct PKeyFree
        {
            void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
        };

        using BioPtr = std::unique_ptr<BIO, BioFree>;
        using X509Ptr = std::unique_ptr<X509, X509Free>;
        using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyFree>;

        std::string OpensslError()
        {
            char buffer[256];
            ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
            return buffer;
        }

        BioPtr OpenPem(const std::string& path, const char* what)
        {
            BioPtr bio(BIO_new_file(path.c_str(), "rb"));
            if (!bio) {
                throw std::runtime_error(std::string("cannot read ") + what + " " + path + ": " + OpensslError());
            }
            return bio;
        }

        std::string NeedValue(int& index, int argc, char** argv, const char* flag)
        {
            if (index + 1 >= argc) {
                throw std::runtime_error(std::string("missing value for ") + flag);
            }
            ++index;
            return argv[index];
        }

        uint16_t ParsePort(const std::string& text, const char* what)
        {
            std::size_t used = 0;
            unsigned long value = 0;
            try {
                value = std::stoul(text, &used, 10);
            } catch (const std::exception&) {
                throw std::runtime_error(std::string(what) + " is not a port");
            }
            if (used != text.size() || value == 0 || value > 65535) {
                throw std::runtime_error(std::string(what) + " must be a UDP port from 1 to 65535");
            }
            return static_cast<uint16_t>(value);
        }

        std::pair<std::string, uint16_t> ParsePeer(const std::string& text)
        {
            const auto colon = text.rfind(':');
            if (colon == std::string::npos || colon == 0 || colon + 1 >= text.size()) {
                throw std::runtime_error("peer must be host:port");
            }
            return { text.substr(0, colon), ParsePort(text.substr(colon + 1), "peer port") };
        }

        NodeType ParseNodeType(const std::string& text)
        {
            if (text == "edge") {
                return NodeType::kEdge;
            }
            if (text == "via") {
                return NodeType::kVia;
            }
            if (text == "stub") {
                return NodeType::kStub;
            }
            throw std::runtime_error("type must be edge, via, or stub");
        }

        void WarnIfKeyIsShared(const std::string& key_path)
        {
#ifndef _WIN32
            struct stat info{};
            if (::stat(key_path.c_str(), &info) != 0) {
                return;
            }
            if ((info.st_mode & (S_IRGRP | S_IROTH)) != 0) {
                std::cerr << "warning: private key " << key_path
                          << " is readable by group or others. Restrict it to the user running this process.\n";
            }
#else
            (void)key_path;
#endif
        }

    } // namespace

    std::string HelpText(ExampleKind kind)
    {
        switch (kind) {
            case ExampleKind::kRelay:
                return "moq_peering_relay --cert FILE --key FILE [--node-id ID] [--type edge|via|stub]\n"
                       "                  [--listen PORT] [--peer HOST:PORT]...\n"
                       "\n"
                       "Forwards announces, subscribes, and objects. It does not publish or subscribe.\n"
                       "edge accepts peers and is the usual parent. via only forwards between relays.\n"
                       "stub dials an edge and is the child of that edge.\n"
                       "\n"
                       "  --cert FILE       PEM certificate this node presents\n"
                       "  --key FILE        Matching unencrypted PEM private key\n"
                       "  --node-id ID      Label hashed as this node's id (default relay)\n"
                       "  --type TYPE       edge, via, or stub (default edge)\n"
                       "  --listen PORT     UDP port (default 33434)\n"
                       "  --peer HOST:PORT  Relay to dial. Repeat for more than one.\n";
            case ExampleKind::kProducer:
                return "moq_peering_producer --cert FILE --key FILE --peer HOST:PORT\n"
                       "                     [--node-id ID] [--listen PORT]\n"
                       "                     [--namespace TEXT] [--track TEXT]\n"
                       "                     [--interval-ms N] [--payload TEXT]\n"
                       "\n"
                       "Dials a relay as a stub, announces one track, and sends a datagram each time\n"
                       "OnPeerSubscribe runs. It keeps sending while a peer remains subscribed.\n"
                       "\n"
                       "  --cert FILE         PEM certificate this node presents\n"
                       "  --key FILE          Matching unencrypted PEM private key\n"
                       "  --peer HOST:PORT    Relay to dial. Repeat to dial more than one.\n"
                       "  --node-id ID        Label hashed as this node's id (default producer)\n"
                       "  --listen PORT       UDP port (default 33450). The relay should not dial this port.\n"
                       "  --namespace TEXT    Track namespace tuple (default demo)\n"
                       "  --track TEXT        Track name (default object)\n"
                       "  --interval-ms N     Milliseconds between later objects (default 1000)\n"
                       "  --payload TEXT      Object text. A sequence number is appended (default hello)\n";
            case ExampleKind::kSubscriber:
                return "moq_peering_subscriber --cert FILE --key FILE --peer HOST:PORT\n"
                       "                       [--node-id ID] [--listen PORT]\n"
                       "                       [--namespace TEXT] [--track TEXT]\n"
                       "\n"
                       "Dials a relay as a stub and subscribes to one track. Object bytes are printed\n"
                       "as they arrive from a producer.\n"
                       "\n"
                       "  --cert FILE       PEM certificate this node presents\n"
                       "  --key FILE        Matching unencrypted PEM private key\n"
                       "  --peer HOST:PORT  Relay to dial. Repeat to dial more than one.\n"
                       "  --node-id ID      Label hashed as this node's id (default subscriber)\n"
                       "  --listen PORT     UDP port (default 33451). The relay should not dial this port.\n"
                       "  --namespace TEXT  Track namespace tuple (default demo)\n"
                       "  --track TEXT      Track name (default object)\n";
        }
        return {};
    }

    ExampleOptions ParseArgs(ExampleKind kind, int argc, char** argv)
    {
        ExampleOptions options;
        switch (kind) {
            case ExampleKind::kRelay:
                options.common.node_id = "relay";
                options.common.node_type = NodeType::kEdge;
                options.common.listen_port = 33434;
                break;
            case ExampleKind::kProducer:
                options.common.node_id = "producer";
                options.common.node_type = NodeType::kStub;
                options.common.listen_port = 33450;
                break;
            case ExampleKind::kSubscriber:
                options.common.node_id = "subscriber";
                options.common.node_type = NodeType::kStub;
                options.common.listen_port = 33451;
                break;
        }

        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                options.common.help = true;
            } else if (arg == "--cert") {
                options.common.cert = NeedValue(i, argc, argv, "--cert");
            } else if (arg == "--key") {
                options.common.key = NeedValue(i, argc, argv, "--key");
            } else if (arg == "--node-id") {
                options.common.node_id = NeedValue(i, argc, argv, "--node-id");
            } else if (arg == "--listen") {
                options.common.listen_port = ParsePort(NeedValue(i, argc, argv, "--listen"), "--listen");
            } else if (arg == "--peer") {
                options.common.peers.push_back(ParsePeer(NeedValue(i, argc, argv, "--peer")));
            } else if (arg == "--type") {
                if (kind != ExampleKind::kRelay) {
                    throw std::runtime_error("--type is only for moq_peering_relay");
                }
                options.common.node_type = ParseNodeType(NeedValue(i, argc, argv, "--type"));
            } else if (arg == "--namespace") {
                if (kind == ExampleKind::kRelay) {
                    throw std::runtime_error("--namespace is not used by moq_peering_relay");
                }
                options.name_space = NeedValue(i, argc, argv, "--namespace");
            } else if (arg == "--track") {
                if (kind == ExampleKind::kRelay) {
                    throw std::runtime_error("--track is not used by moq_peering_relay");
                }
                options.track = NeedValue(i, argc, argv, "--track");
            } else if (arg == "--interval-ms") {
                if (kind != ExampleKind::kProducer) {
                    throw std::runtime_error("--interval-ms is only for moq_peering_producer");
                }
                const auto text = NeedValue(i, argc, argv, "--interval-ms");
                std::size_t used = 0;
                unsigned long value = 0;
                try {
                    value = std::stoul(text, &used, 10);
                } catch (const std::exception&) {
                    throw std::runtime_error("--interval-ms is not a number");
                }
                if (used != text.size() || value == 0 || value > 600000) {
                    throw std::runtime_error("--interval-ms must be from 1 to 600000");
                }
                options.interval_ms = static_cast<int>(value);
            } else if (arg == "--payload") {
                if (kind != ExampleKind::kProducer) {
                    throw std::runtime_error("--payload is only for moq_peering_producer");
                }
                options.payload = NeedValue(i, argc, argv, "--payload");
            } else {
                throw std::runtime_error("unknown argument " + arg);
            }
        }

        if (options.common.help) {
            return options;
        }
        if (options.common.cert.empty() || options.common.key.empty()) {
            throw std::runtime_error("pass --cert and --key. Create a development pair with: make cert");
        }
        if (options.common.node_id.empty()) {
            throw std::runtime_error("--node-id must not be empty");
        }
        if (kind != ExampleKind::kRelay && options.common.peers.empty()) {
            throw std::runtime_error("pass --peer host:port for the relay to dial");
        }
        if (kind != ExampleKind::kRelay && (options.name_space.empty() || options.track.empty())) {
            throw std::runtime_error("--namespace and --track must not be empty");
        }
        if (!std::filesystem::is_regular_file(options.common.cert)) {
            throw std::runtime_error("certificate file not found: " + options.common.cert);
        }
        if (!std::filesystem::is_regular_file(options.common.key)) {
            throw std::runtime_error("private key file not found: " + options.common.key);
        }
        return options;
    }

    void CheckCertificate(const std::string& cert_path, const std::string& key_path)
    {
        auto cert_bio = OpenPem(cert_path, "certificate");
        X509Ptr cert(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
        if (!cert) {
            throw std::runtime_error("failed to parse certificate " + cert_path + ": " + OpensslError());
        }

        // X509_cmp_time returns -1 when the field is earlier than now.
        const int not_before = X509_cmp_time(X509_get0_notBefore(cert.get()), nullptr);
        const int not_after = X509_cmp_time(X509_get0_notAfter(cert.get()), nullptr);
        if (not_before == 0 || not_after == 0) {
            throw std::runtime_error("could not read the certificate validity dates");
        }
        if (not_before > 0) {
            throw std::runtime_error("certificate is not yet valid: " + cert_path);
        }
        if (not_after < 0) {
            throw std::runtime_error("certificate is expired: " + cert_path);
        }

        PKeyPtr public_key(X509_get_pubkey(cert.get()));
        if (!public_key) {
            throw std::runtime_error("certificate has no public key: " + cert_path);
        }
        const int key_type = EVP_PKEY_get_id(public_key.get());
        const int bits = EVP_PKEY_get_bits(public_key.get());
        if (key_type == EVP_PKEY_RSA && bits < 2048) {
            throw std::runtime_error("certificate RSA key is weaker than 2048 bits");
        }
        if (key_type == EVP_PKEY_EC && bits < 256) {
            throw std::runtime_error("certificate EC key is weaker than P-256");
        }
        if (key_type != EVP_PKEY_RSA && key_type != EVP_PKEY_EC) {
            throw std::runtime_error("certificate public key must be RSA 2048 or ECDSA P-256 or stronger");
        }

        int digest_nid = NID_undef;
        int pkey_nid = NID_undef;
        if (OBJ_find_sigid_algs(X509_get_signature_nid(cert.get()), &digest_nid, &pkey_nid) != 1) {
            throw std::runtime_error("could not read the certificate signature algorithm");
        }
        if (digest_nid == NID_md5 || digest_nid == NID_sha1 || digest_nid == NID_md2 || digest_nid == NID_md4) {
            throw std::runtime_error("certificate is signed with MD5 or SHA-1. Use a SHA-2 signature.");
        }

        if (X509_NAME_cmp(X509_get_subject_name(cert.get()), X509_get_issuer_name(cert.get())) == 0) {
            std::cerr << "note: " << cert_path << " is self-signed. That is fine for these development examples. "
                      << "Do not use it for a public deployment.\n";
        }

        auto key_bio = OpenPem(key_path, "private key");
        PKeyPtr private_key(PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
        if (!private_key) {
            throw std::runtime_error("failed to parse private key " + key_path +
                                     ". The example expects an unencrypted PEM key. " + OpensslError());
        }
        if (X509_check_private_key(cert.get(), private_key.get()) != 1) {
            throw std::runtime_error("private key does not match the certificate");
        }
        WarnIfKeyIsShared(key_path);
    }

    std::shared_ptr<spdlog::logger> MakeLogger(const std::string& node_id)
    {
        auto logger = spdlog::stdout_color_mt(node_id);
        logger->set_level(spdlog::level::info);
        logger->flush_on(spdlog::level::info);
        return logger;
    }

    Config MakeConfig(const CommonOptions& options, const std::shared_ptr<spdlog::logger>& logger)
    {
        Config config;
        config.node_id = options.node_id;
        config.node_type = options.node_type;
        config.listen_port = options.listen_port;
        config.peers = options.peers;
        config.tls_cert_filename = options.cert;
        config.tls_key_filename = options.key;
        // The check thread sleeps half of this. 2000 is the shortest the library allows.
        config.check_interval_ms = 2000;
        config.logger = logger;
        return config;
    }

    TrackName MakeTrack(const std::string& name_space, const std::string& track)
    {
        TrackName name;
        name.name_space.push_back({ name_space.begin(), name_space.end() });
        name.name.assign(track.begin(), track.end());
        return name;
    }

    std::string FormatTrack(const TrackName& name)
    {
        std::string text;
        for (const auto& part : name.name_space) {
            if (!text.empty()) {
                text.push_back('/');
            }
            text.append(part.begin(), part.end());
        }
        text.push_back('/');
        text.append(name.name.begin(), name.name.end());
        return text;
    }

    void WaitForInterrupt()
    {
        std::signal(SIGINT, OnSignal);
        std::signal(SIGTERM, OnSignal);
        while (g_stop == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

} // namespace moq::peering::examples
