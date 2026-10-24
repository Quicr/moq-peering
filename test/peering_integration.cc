// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

// Relays in one process, over the real QUIC transport. No MoQ session is opened.
//
// Each test generates a short-lived certificate instead of embedding one. The certificate is
// self-signed on P-256 with SHA-256, valid for this run only, and removed with its private key
// when the test ends. It is for this test process, not for production.

#include <doctest/doctest.h>

#include <moq/peering/peer_manager.h>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

    using namespace moq::peering;

    constexpr auto kWait = std::chrono::seconds(10);

    // --- ephemeral test certificate -----------------------------------------
    // No credential material is stored in the source tree. OpenSSL generates a P-256 key with its
    // CSPRNG, the certificate is signed with SHA-256, and both files live in a private temp directory.

    struct FileBio
    {
        explicit FileBio(const std::filesystem::path& path, const char* mode)
          : bio(BIO_new_file(path.string().c_str(), mode))
        {
            if (bio == nullptr) {
                throw std::runtime_error("failed to open " + path.string());
            }
        }

        ~FileBio() { BIO_free(bio); }

        FileBio(const FileBio&) = delete;
        FileBio& operator=(const FileBio&) = delete;

        BIO* bio;
    };

    [[noreturn]] void FailOpenSsl(const std::string& what)
    {
        char buffer[256];
        ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
        throw std::runtime_error(what + ": " + buffer);
    }

    void VerifyGeneratedCertificate(X509* cert, EVP_PKEY* key)
    {
        // notBefore must be in the past and notAfter in the future. X509_cmp_time returns -1 when the
        // certificate time is earlier than now, and 1 when it is later.
        const int not_before = X509_cmp_time(X509_get0_notBefore(cert), nullptr);
        const int not_after = X509_cmp_time(X509_get0_notAfter(cert), nullptr);
        if (not_before != -1) {
            throw std::runtime_error("generated test certificate is not yet valid");
        }
        if (not_after != 1) {
            throw std::runtime_error("generated test certificate is already expired");
        }

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> public_key(X509_get_pubkey(cert), &EVP_PKEY_free);
        if (!public_key || EVP_PKEY_get_base_id(public_key.get()) != EVP_PKEY_EC ||
            EVP_PKEY_get_bits(public_key.get()) < 256) {
            throw std::runtime_error("generated test certificate must use an ECDSA P-256 key or stronger");
        }

        if (X509_get_signature_nid(cert) != NID_ecdsa_with_SHA256) {
            throw std::runtime_error("generated test certificate must be signed with ecdsa-with-SHA256");
        }

        // Self-signed is intentional: the peering transport does not validate peer certificates, and this
        // material exists only for the test process.
        if (X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) != 0) {
            throw std::runtime_error("generated test certificate should be self-signed");
        }

        if (EVP_PKEY_eq(public_key.get(), key) != 1) {
            throw std::runtime_error("generated test certificate does not match its private key");
        }
    }

    class TestIdentity
    {
      public:
        TestIdentity()
        {
            std::random_device random;
            directory_ = std::filesystem::temp_directory_path() /
                         ("moq-peering-it-" + std::to_string(random()) + "-" + std::to_string(random()));
            std::filesystem::create_directories(directory_);
            std::error_code ec;
            std::filesystem::permissions(directory_, std::filesystem::perms::owner_all, ec);

            cert_path_ = directory_ / "cert.pem";
            key_path_ = directory_ / "key.pem";

            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"),
                                                                    &EVP_PKEY_free);
            if (!key) {
                FailOpenSsl("failed to generate a P-256 test key");
            }

            std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), &X509_free);
            if (!cert) {
                FailOpenSsl("failed to allocate a test certificate");
            }

            if (X509_set_version(cert.get(), 2) != 1) {
                FailOpenSsl("failed to set the test certificate version");
            }
            if (ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1) {
                FailOpenSsl("failed to set the test certificate serial");
            }

            X509_NAME* name = X509_get_subject_name(cert.get());
            const unsigned char common_name[] = "moq-peering-test";
            if (X509_NAME_add_entry_by_txt(
                  name, "CN", MBSTRING_ASC, common_name, -1, -1, 0) != 1) {
                FailOpenSsl("failed to set the test certificate subject");
            }
            if (X509_set_issuer_name(cert.get(), name) != 1) {
                FailOpenSsl("failed to set the test certificate issuer");
            }

            // One hour of clock skew, then one day of validity. The key is thrown away with the temp directory.
            if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) == nullptr ||
                X509_gmtime_adj(X509_getm_notAfter(cert.get()), 24 * 3600) == nullptr) {
                FailOpenSsl("failed to set the test certificate validity");
            }
            if (X509_set_pubkey(cert.get(), key.get()) != 1) {
                FailOpenSsl("failed to set the test certificate public key");
            }
            if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
                FailOpenSsl("failed to sign the test certificate");
            }

            {
                FileBio cert_out(cert_path_, "wb");
                if (PEM_write_bio_X509(cert_out.bio, cert.get()) != 1) {
                    FailOpenSsl("failed to write the test certificate");
                }
            }
            {
                FileBio key_out(key_path_, "wb");
                if (PEM_write_bio_PrivateKey(key_out.bio, key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                    FailOpenSsl("failed to write the test private key");
                }
            }
            std::filesystem::permissions(
              key_path_, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, ec);

            FileBio cert_in(cert_path_, "rb");
            std::unique_ptr<X509, decltype(&X509_free)> loaded(PEM_read_bio_X509(cert_in.bio, nullptr, nullptr, nullptr),
                                                               &X509_free);
            if (!loaded) {
                FailOpenSsl("failed to read back the test certificate");
            }
            VerifyGeneratedCertificate(loaded.get(), key.get());

            cert_string_ = cert_path_.string();
            key_string_ = key_path_.string();
        }

        ~TestIdentity()
        {
            std::error_code ec;
            std::filesystem::remove_all(directory_, ec);
        }

        TestIdentity(const TestIdentity&) = delete;
        TestIdentity& operator=(const TestIdentity&) = delete;

        const std::string& cert() const { return cert_string_; }
        const std::string& key() const { return key_string_; }

      private:
        std::filesystem::path directory_;
        std::filesystem::path cert_path_;
        std::filesystem::path key_path_;
        std::string cert_string_;
        std::string key_string_;
    };

    std::uint16_t EphemeralPort()
    {
#ifdef _WIN32
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
        const SOCKET fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == INVALID_SOCKET) {
            throw std::runtime_error("failed to open a UDP socket for an ephemeral port");
        }
#else
        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            throw std::runtime_error("failed to open a UDP socket for an ephemeral port");
        }
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
#ifdef _WIN32
            ::closesocket(fd);
#else
            ::close(fd);
#endif
            throw std::runtime_error("failed to bind an ephemeral UDP port");
        }

        socklen_t length = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &length) != 0) {
#ifdef _WIN32
            ::closesocket(fd);
#else
            ::close(fd);
#endif
            throw std::runtime_error("failed to read an ephemeral UDP port");
        }

        const auto port = ntohs(addr.sin_port);
#ifdef _WIN32
        ::closesocket(fd);
#else
        ::close(fd);
#endif
        if (port == 0) {
            throw std::runtime_error("ephemeral UDP port was 0");
        }
        return port;
    }

    TrackName MakeTrack(std::string_view name_space, std::string_view track)
    {
        TrackName name;
        name.name_space.push_back({ name_space.begin(), name_space.end() });
        name.name.assign(track.begin(), track.end());
        return name;
    }

    std::vector<uint8_t> Bytes(std::string_view text)
    {
        return { text.begin(), text.end() };
    }

    bool SameTrack(const TrackName& left, const TrackName& right)
    {
        return left.name == right.name && left.name_space == right.name_space;
    }

    std::string BytesAsText(const std::vector<uint8_t>& bytes)
    {
        return { bytes.begin(), bytes.end() };
    }

    class Relay
    {
      public:
        Relay(std::string node_id,
              NodeType type,
              std::vector<std::pair<std::string, uint16_t>> peers,
              const TestIdentity& identity)
          : port_(EphemeralPort())
        {
            static std::atomic<int> logger_seq{ 0 };

            Config config;
            config.node_id = std::move(node_id);
            config.node_type = type;
            config.listen_port = port_;
            config.peers = std::move(peers);
            config.tls_cert_filename = identity.cert();
            config.tls_key_filename = identity.key();
            config.check_interval_ms = 2000;

            const auto logger_name = "itest-" + config.node_id + "-" + std::to_string(logger_seq.fetch_add(1));
            logger_ = spdlog::stdout_color_mt(logger_name);
            logger_->set_level(spdlog::level::info);
            logger_->flush_on(spdlog::level::info);
            config.logger = logger_;

            try {
                node_ = std::make_unique<PeerManager>(config);
            } catch (const std::exception& ex) {
                throw std::runtime_error("failed to start relay " + config.node_id + ": " + ex.what());
            }
            node_->SetDelegate(&app_);
            app_.peers = node_.get();
        }

        ~Relay()
        {
            if (node_) {
                node_->SetDelegate(nullptr);
            }
            node_.reset();
            if (logger_) {
                spdlog::drop(logger_->name());
            }
        }

        Relay(const Relay&) = delete;
        Relay& operator=(const Relay&) = delete;

        uint16_t port() const { return port_; }

        void Publish(const TrackName& name, std::vector<uint8_t> payload)
        {
            const auto hash = PeerManager::HashTrack(name);
            {
                std::lock_guard lock(app_.mu);
                app_.published[hash] = std::move(payload);
            }
            node_->Announce(name, Announcement::kTrack);
        }

        void Subscribe(const TrackName& name)
        {
            SubscribeParams params;
            params.priority = 10;
            params.delivery_timeout_ms = 1000;
            params.forward = 1;
            node_->Subscribe(name, params);
        }

        int PeersDown()
        {
            std::lock_guard lock(app_.mu);
            return app_.peers_down;
        }

        bool WaitPeersDown(int target, std::chrono::milliseconds timeout)
        {
            std::unique_lock lock(app_.mu);
            return app_.cv.wait_for(lock, timeout, [&] { return app_.peers_down >= target; });
        }

        bool WaitTrack(const TrackName& name, std::chrono::milliseconds timeout)
        {
            std::unique_lock lock(app_.mu);
            return app_.cv.wait_for(lock, timeout, [&] { return app_.HasTrack(name); });
        }

        bool WaitPayload(std::uint64_t track_hash, std::chrono::milliseconds timeout)
        {
            std::unique_lock lock(app_.mu);
            return app_.cv.wait_for(lock, timeout, [&] { return app_.received.contains(track_hash); });
        }

        std::vector<uint8_t> Payload(std::uint64_t track_hash)
        {
            std::lock_guard lock(app_.mu);
            return app_.received.at(track_hash);
        }

        bool SawSubscribe(std::uint64_t track_hash)
        {
            std::lock_guard lock(app_.mu);
            return app_.subscribes.contains(track_hash);
        }

        std::size_t PayloadCount()
        {
            std::lock_guard lock(app_.mu);
            return app_.received.size();
        }

        std::string Debug()
        {
            std::lock_guard lock(app_.mu);
            std::ostringstream out;
            out << "peers_up=" << app_.peers_up << " tracks=" << app_.tracks.size()
                << " subscribes=" << app_.subscribes.size() << " payloads=" << app_.received.size();
            return out.str();
        }

      private:
        class App : public Delegate
        {
          public:
            PeerManager* peers{ nullptr };
            std::mutex mu;
            std::condition_variable cv;
            int peers_up{ 0 };
            int peers_down{ 0 };
            std::map<std::uint64_t, std::vector<uint8_t>> published;
            std::map<std::uint64_t, std::vector<uint8_t>> received;
            std::vector<TrackName> tracks;
            std::map<std::uint64_t, int> subscribes;

            bool HasTrack(const TrackName& name) const
            {
                for (const auto& track : tracks) {
                    if (SameTrack(track, name)) {
                        return true;
                    }
                }
                return false;
            }

            void OnPeerUp(std::uint64_t) override
            {
                {
                    std::lock_guard lock(mu);
                    ++peers_up;
                }
                cv.notify_all();
            }

            void OnPeerDown(std::uint64_t) override
            {
                {
                    std::lock_guard lock(mu);
                    ++peers_down;
                }
                cv.notify_all();
            }

            void OnPeerSubscribe(const TrackName&, std::uint64_t track_hash, const SubscribeParams&) override
            {
                std::vector<uint8_t> payload;
                bool send = false;
                {
                    std::lock_guard lock(mu);
                    ++subscribes[track_hash];
                    if (const auto it = published.find(track_hash); it != published.end()) {
                        payload = it->second;
                        send = true;
                    }
                }

                if (send && peers != nullptr) {
                    auto bytes = std::make_shared<std::vector<uint8_t>>(std::move(payload));
                    peers->SendData(track_hash, 10, 1000, DataType::kDatagram, 1, 0, std::move(bytes));
                }
                cv.notify_all();
            }

            void OnPeerTrack(const TrackName& name, bool withdrawn) override
            {
                {
                    std::lock_guard lock(mu);
                    if (withdrawn) {
                        std::erase_if(tracks, [&](const TrackName& track) { return SameTrack(track, name); });
                    } else if (!HasTrack(name)) {
                        tracks.push_back(name);
                    }
                }
                cv.notify_all();
            }

            void OnPeerData(std::uint64_t track_hash,
                            bool,
                            std::optional<std::uint64_t>,
                            std::shared_ptr<const std::vector<uint8_t>> data) override
            {
                if (!data) {
                    return;
                }
                {
                    std::lock_guard lock(mu);
                    received[track_hash] = *data;
                }
                cv.notify_all();
            }
        };

        uint16_t port_;
        App app_;
        std::unique_ptr<PeerManager> node_;
        std::shared_ptr<spdlog::logger> logger_;
    };

    void Exchange(Relay& left,
                  const TrackName& left_track,
                  const std::vector<uint8_t>& left_payload,
                  Relay& right,
                  const TrackName& right_track,
                  const std::vector<uint8_t>& right_payload)
    {
        const auto left_hash = PeerManager::HashTrack(left_track);
        const auto right_hash = PeerManager::HashTrack(right_track);

        left.Publish(left_track, left_payload);
        right.Publish(right_track, right_payload);

        INFO("left " << left.Debug());
        INFO("right " << right.Debug());
        REQUIRE_MESSAGE(left.WaitTrack(right_track, kWait), "timed out waiting for the right-hand track announcement");
        REQUIRE_MESSAGE(right.WaitTrack(left_track, kWait), "timed out waiting for the left-hand track announcement");

        left.Subscribe(right_track);
        right.Subscribe(left_track);

        REQUIRE_MESSAGE(left.WaitPayload(right_hash, kWait), "timed out waiting for the right-hand object");
        REQUIRE_MESSAGE(right.WaitPayload(left_hash, kWait), "timed out waiting for the left-hand object");

        CHECK(BytesAsText(left.Payload(right_hash)) == BytesAsText(right_payload));
        CHECK(BytesAsText(right.Payload(left_hash)) == BytesAsText(left_payload));
        CHECK(left.SawSubscribe(left_hash));
        CHECK(right.SawSubscribe(right_hash));
    }

} // namespace

TEST_CASE("Two relays exchange publish, subscribe, and data")
{
    // listener (edge) <--dial-- dialer (edge)
    const TestIdentity identity;

    Relay listener("edge-a", NodeType::kEdge, {}, identity);
    Relay dialer("edge-b", NodeType::kEdge, { { "127.0.0.1", listener.port() } }, identity);

    const auto left_track = MakeTrack("edge-a", "object");
    const auto right_track = MakeTrack("edge-b", "object");
    Exchange(listener, left_track, Bytes("from-a"), dialer, right_track, Bytes("from-b"));
}

TEST_CASE("Three relays in a chain forward through a via")
{
    // left (edge) <--dial-- via (kVia) <--dial-- right (edge)
    // The via does not publish. It forwards announces, subscribes, and datagrams both ways.
    const TestIdentity identity;

    Relay left("edge-left", NodeType::kEdge, {}, identity);
    Relay via("via-mid", NodeType::kVia, { { "127.0.0.1", left.port() } }, identity);
    Relay right("edge-right", NodeType::kEdge, { { "127.0.0.1", via.port() } }, identity);

    const auto left_track = MakeTrack("edge-left", "object");
    const auto right_track = MakeTrack("edge-right", "object");
    Exchange(left, left_track, Bytes("from-left"), right, right_track, Bytes("from-right"));

    const auto left_hash = PeerManager::HashTrack(left_track);
    const auto right_hash = PeerManager::HashTrack(right_track);
    REQUIRE_MESSAGE(via.WaitTrack(left_track, kWait), "via did not observe the left announcement");
    REQUIRE_MESSAGE(via.WaitTrack(right_track, kWait), "via did not observe the right announcement");
    CHECK(via.SawSubscribe(left_hash));
    CHECK(via.SawSubscribe(right_hash));
    CHECK(via.PayloadCount() == 0);
}

TEST_CASE("Dropping the via relay does not crash the edges")
{
    // left <--dial-- via <--dial-- right, then the via goes away.
    // Each edge still holds the other edge's subscribe, learned through the via. Tearing that
    // session down must withdraw those subscribes without throwing.
    const TestIdentity identity;

    Relay left("edge-left", NodeType::kEdge, {}, identity);
    auto via = std::make_unique<Relay>(
      "via-mid",
      NodeType::kVia,
      std::vector<std::pair<std::string, uint16_t>>{ { "127.0.0.1", left.port() } },
      identity);
    Relay right("edge-right", NodeType::kEdge, { { "127.0.0.1", via->port() } }, identity);

    const auto left_track = MakeTrack("edge-left", "object");
    const auto right_track = MakeTrack("edge-right", "object");
    Exchange(left, left_track, Bytes("from-left"), right, right_track, Bytes("from-right"));

    const int left_down = left.PeersDown();
    const int right_down = right.PeersDown();
    via.reset();

    REQUIRE_MESSAGE(left.WaitPeersDown(left_down + 1, kWait), "left did not observe the via disconnect");
    REQUIRE_MESSAGE(right.WaitPeersDown(right_down + 1, kWait), "right did not observe the via disconnect");
}

TEST_CASE("Three relays with a stub exchange publish, subscribe, and data")
{
    // stub (kStub) --dial--> parent (edge) <--dial-- far (edge)
    // Nothing dials the stub. The parent forwards between the stub and the far edge.
    const TestIdentity identity;

    Relay parent("edge-parent", NodeType::kEdge, {}, identity);
    // `far` is an empty macro in the Windows headers pulled in by winsock.
    Relay far_edge("edge-far", NodeType::kEdge, { { "127.0.0.1", parent.port() } }, identity);
    Relay stub("stub", NodeType::kStub, { { "127.0.0.1", parent.port() } }, identity);

    const auto stub_track = MakeTrack("stub", "object");
    const auto far_track = MakeTrack("edge-far", "object");
    Exchange(stub, stub_track, Bytes("from-stub"), far_edge, far_track, Bytes("from-far"));

    const auto stub_hash = PeerManager::HashTrack(stub_track);
    const auto far_hash = PeerManager::HashTrack(far_track);
    REQUIRE_MESSAGE(parent.WaitTrack(stub_track, kWait), "parent did not observe the stub announcement");
    REQUIRE_MESSAGE(parent.WaitTrack(far_track, kWait), "parent did not observe the far announcement");
    CHECK(parent.SawSubscribe(stub_hash));
    CHECK(parent.SawSubscribe(far_hash));
    CHECK(parent.PayloadCount() == 0);
}
