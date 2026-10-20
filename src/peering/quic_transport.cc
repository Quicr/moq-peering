// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include "quic_transport.h"

#include <picoquic_bbr.h>
#include <picosocks.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <random>
#include <stdexcept>

extern "C" void picoquic_init_transport_parameters(picoquic_tp_t* tp);

namespace moq::peering {
    namespace {
        constexpr char kAlpn[] = "moq-peering";
        constexpr uint64_t kIdleTimeoutMs = 5000;

        bool IsBidirectional(uint64_t stream_id)
        {
            return (stream_id & PICOQUIC_STREAM_ID_UNIDIR) == 0;
        }

        void ApplyTransportParameters(picoquic_quic_t* quic)
        {
            picoquic_tp_t tp;
            picoquic_init_transport_parameters(&tp);
            tp.max_datagram_frame_size = 1280;
            tp.max_idle_timeout = kIdleTimeoutMs;
            tp.max_ack_delay = 100000;
            tp.min_ack_delay = 1000;
            if (tp.initial_max_stream_data_uni == 0) {
                tp.initial_max_stream_data_uni = 1u << 20;
                tp.initial_max_stream_data_bidi_local = 1u << 20;
                tp.initial_max_stream_data_bidi_remote = 1u << 20;
                tp.initial_max_data = 16u << 20;
            }
            if (tp.initial_max_stream_id_unidir < 512) {
                tp.initial_max_stream_id_bidir = 2048;
                tp.initial_max_stream_id_unidir = 4096;
            }
            picoquic_set_default_tp(quic, &tp);
        }
    }

    QuicConnection::QuicConnection(std::shared_ptr<QuicEndpoint> endpoint, picoquic_cnx_t* cnx, uint64_t id)
      : endpoint_(std::move(endpoint))
      , cnx_(cnx)
      , id_(id)
    {
    }

    void QuicConnection::SetHandlers(Handlers handlers)
    {
        std::lock_guard lock(handler_mutex_);
        handlers_ = std::move(handlers);
    }

    void QuicConnection::Run(std::function<void()> fn)
    {
        endpoint_->Run(std::move(fn));
    }

    std::pair<std::string, uint16_t> QuicConnection::PeerAddress() const
    {
        std::pair<std::string, uint16_t> result{ "", 0 };
        auto self = const_cast<QuicConnection*>(this);
        self->Run([this, &result] {
            if (cnx_ == nullptr) {
                return;
            }
            struct sockaddr* addr = nullptr;
            picoquic_get_peer_addr(cnx_, &addr);
            if (addr == nullptr) {
                return;
            }
            char text[INET6_ADDRSTRLEN] = {};
            if (addr->sa_family == AF_INET) {
                const auto* in = reinterpret_cast<sockaddr_in*>(addr);
                inet_ntop(AF_INET, &in->sin_addr, text, sizeof(text));
                result = { text, ntohs(in->sin_port) };
            } else if (addr->sa_family == AF_INET6) {
                const auto* in6 = reinterpret_cast<sockaddr_in6*>(addr);
                inet_ntop(AF_INET6, &in6->sin6_addr, text, sizeof(text));
                result = { text, ntohs(in6->sin6_port) };
            }
        });
        return result;
    }

    uint64_t QuicConnection::RttUs() const
    {
        uint64_t rtt = 0;
        auto self = const_cast<QuicConnection*>(this);
        self->Run([this, &rtt] {
            if (cnx_ != nullptr) {
                rtt = picoquic_get_rtt(cnx_);
            }
        });
        return rtt;
    }

    std::shared_ptr<QuicStream> QuicConnection::OpenBidirectional(uint8_t priority)
    {
        auto stream = std::make_shared<QuicStream>();
        stream->bidirectional = true;
        stream->id = UINT64_MAX;
        Run([this, stream, priority] {
            if (cnx_ == nullptr || closing_) {
                return;
            }
            stream->id = picoquic_get_next_local_stream_id(cnx_, 0);
            picoquic_set_stream_priority(cnx_, stream->id, priority);
        });
        if (stream->id == UINT64_MAX) {
            return nullptr;
        }
        return stream;
    }

    std::shared_ptr<QuicStream> QuicConnection::OpenUnidirectional(uint8_t priority)
    {
        auto stream = std::make_shared<QuicStream>();
        stream->id = UINT64_MAX;
        Run([this, stream, priority] {
            if (cnx_ == nullptr || closing_) {
                return;
            }
            stream->id = picoquic_get_next_local_stream_id(cnx_, 1);
            picoquic_set_stream_priority(cnx_, stream->id, priority);
        });
        if (stream->id == UINT64_MAX) {
            return nullptr;
        }
        return stream;
    }

    void QuicConnection::Send(uint64_t stream_id, std::span<const uint8_t> data, bool fin)
    {
        std::vector<uint8_t> bytes(data.begin(), data.end());
        Run([this, stream_id, bytes = std::move(bytes), fin] {
            if (cnx_ == nullptr || closing_) {
                return;
            }
            picoquic_add_to_stream(cnx_, stream_id, bytes.empty() ? nullptr : bytes.data(), bytes.size(), fin ? 1 : 0);
        });
    }

    void QuicConnection::SendDatagram(std::span<const uint8_t> data)
    {
        std::vector<uint8_t> bytes(data.begin(), data.end());
        Run([this, bytes = std::move(bytes)] {
            if (cnx_ == nullptr || closing_ || bytes.empty()) {
                return;
            }
            picoquic_queue_datagram_frame(cnx_, bytes.size(), bytes.data());
        });
    }

    void QuicConnection::Reset(uint64_t stream_id)
    {
        Run([this, stream_id] {
            if (cnx_ != nullptr && !closing_) {
                picoquic_reset_stream(cnx_, stream_id, 0);
            }
        });
    }

    void QuicConnection::StopSending(uint64_t stream_id)
    {
        Run([this, stream_id] {
            if (cnx_ != nullptr && !closing_) {
                picoquic_stop_sending(cnx_, stream_id, 0);
            }
        });
    }

    void QuicConnection::Start()
    {
        Run([this] {
            if (cnx_ != nullptr && !closing_) {
                picoquic_start_client_cnx(cnx_);
            }
        });
    }

    void QuicConnection::Close()
    {
        Run([this] {
            if (cnx_ == nullptr || closing_) {
                return;
            }
            closing_ = true;
            picoquic_set_callback(cnx_, nullptr, nullptr);
            picoquic_close(cnx_, 0);
            cnx_ = nullptr;
        });
        if (endpoint_) {
            endpoint_->Release(id_);
        }
    }

    int QuicConnection::Callback(picoquic_cnx_t*,
                                 uint64_t stream_id,
                                 uint8_t* bytes,
                                 size_t length,
                                 picoquic_call_back_event_t event,
                                 void* callback_ctx,
                                 void*)
    {
        auto* self = static_cast<QuicConnection*>(callback_ctx);
        if (self == nullptr || self->closing_) {
            return 0;
        }
        return self->OnEvent(stream_id, bytes, length, event);
    }

    int QuicConnection::OnEvent(uint64_t stream_id, uint8_t* bytes, size_t length, picoquic_call_back_event_t event)
    {
        Handlers handlers;
        {
            std::lock_guard lock(handler_mutex_);
            handlers = handlers_;
        }

        switch (event) {
            case picoquic_callback_ready:
                if (handlers.on_ready) {
                    handlers.on_ready();
                }
                break;
            case picoquic_callback_stream_data:
            case picoquic_callback_stream_fin:
                if (handlers.on_stream && (length > 0 || event == picoquic_callback_stream_fin)) {
                    std::vector<uint8_t> data;
                    if (bytes != nullptr && length > 0) {
                        data.assign(bytes, bytes + length);
                    }
                    handlers.on_stream(stream_id, IsBidirectional(stream_id), std::move(data),
                                       event == picoquic_callback_stream_fin);
                }
                if (event == picoquic_callback_stream_fin && handlers.on_stream_closed) {
                    handlers.on_stream_closed(stream_id, StreamClose::kFin);
                }
                break;
            case picoquic_callback_datagram:
                if (handlers.on_datagram && bytes != nullptr && length > 0) {
                    handlers.on_datagram(std::vector<uint8_t>(bytes, bytes + length));
                }
                break;
            case picoquic_callback_stream_reset:
                if (handlers.on_stream_closed) {
                    handlers.on_stream_closed(stream_id, StreamClose::kReset);
                }
                break;
            case picoquic_callback_stop_sending:
                if (handlers.on_stream_closed) {
                    handlers.on_stream_closed(stream_id, StreamClose::kStopSending);
                }
                break;
            case picoquic_callback_close:
            case picoquic_callback_application_close:
            case picoquic_callback_stateless_reset:
                if (!closed_notified_) {
                    closed_notified_ = true;
                    closing_ = true;
                    cnx_ = nullptr;
                    auto self = shared_from_this();
                    if (handlers.on_closed) {
                        handlers.on_closed();
                    }
                    endpoint_->Release(id_);
                    (void)self;
                }
                break;
            default:
                break;
        }
        return 0;
    }

    QuicEndpoint::QuicEndpoint(std::string cert_file, std::string key_file, uint16_t port, bool server, AcceptFn on_accept)
      : cert_file_(std::move(cert_file))
      , key_file_(std::move(key_file))
      , port_(port)
      , server_(server)
      , on_accept_(std::move(on_accept))
    {
        uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE];
        std::random_device random;
        for (auto& byte : reset_seed) {
            byte = static_cast<uint8_t>(random());
        }

        quic_ = picoquic_create(server_ ? 100 : 4,
                                cert_file_.empty() ? nullptr : cert_file_.c_str(),
                                key_file_.empty() ? nullptr : key_file_.c_str(),
                                nullptr,
                                kAlpn,
                                server_ ? &QuicEndpoint::ServerCallback : nullptr,
                                server_ ? this : nullptr,
                                nullptr,
                                nullptr,
                                reset_seed,
                                picoquic_current_time(),
                                nullptr,
                                nullptr,
                                nullptr,
                                0);
        if (quic_ == nullptr) {
            throw std::runtime_error("Failed to create picoquic context; check the certificate and key files");
        }

        // No trust anchor is configured. picoquic then leaves peer-certificate checks disabled, which
        // is how relays with distinct certificates can peer. The local certificate is still loaded
        // from the path above and presented as this node's identity. TLS stays inside picoquic.
        picoquic_set_client_authentication(quic_, 0);

        picoquic_set_default_congestion_algorithm(quic_, picoquic_bbr_algorithm);
        picoquic_set_default_idle_timeout(quic_, kIdleTimeoutMs);
        picoquic_set_default_priority(quic_, 2);
        picoquic_set_default_datagram_priority(quic_, 1);
        ApplyTransportParameters(quic_);
        active_ = true;
    }

    std::shared_ptr<QuicEndpoint> QuicEndpoint::Listen(const std::string& cert_file,
                                                       const std::string& key_file,
                                                       uint16_t port,
                                                       AcceptFn on_accept)
    {
        auto endpoint =
          std::shared_ptr<QuicEndpoint>(new QuicEndpoint(cert_file, key_file, port, true, std::move(on_accept)));
        endpoint->StartThread();
        return endpoint;
    }

    void QuicEndpoint::StartThread()
    {
        loop_params_ = {};
        loop_params_.local_port = port_;
        loop_params_.local_af = AF_UNSPEC;

        int loop_ret = 0;
        thread_ = picoquic_start_network_thread(quic_, &loop_params_, &QuicEndpoint::LoopCallback, this, &loop_ret);
        if (thread_ == nullptr) {
            throw std::runtime_error("Failed to start the picoquic network thread");
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!thread_->thread_is_ready && thread_->return_code == 0 && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!thread_->thread_is_ready || thread_->return_code != 0) {
            throw std::runtime_error("picoquic network thread failed to bind");
        }
    }

    QuicEndpoint::~QuicEndpoint()
    {
        Shutdown();
    }

    void QuicEndpoint::Shutdown()
    {
        active_ = false;
        if (thread_ != nullptr) {
            picoquic_delete_network_thread(thread_);
            thread_ = nullptr;
        }
        if (quic_ != nullptr) {
            picoquic_free(quic_);
            quic_ = nullptr;
        }
        std::lock_guard lock(connections_mutex_);
        for (auto& [id, connection] : connections_) {
            (void)id;
            if (connection) {
                connection->cnx_ = nullptr;
                connection->closing_ = true;
            }
        }
        connections_.clear();
    }

    void QuicEndpoint::Post(std::function<void()> fn)
    {
        {
            std::lock_guard lock(queue_mutex_);
            queue_.push_back(std::move(fn));
        }
        if (thread_ != nullptr) {
            picoquic_wake_up_network_thread(thread_);
        }
    }

    void QuicEndpoint::Drain()
    {
        std::vector<std::function<void()>> batch;
        {
            std::lock_guard lock(queue_mutex_);
            batch.swap(queue_);
        }
        for (auto& fn : batch) {
            fn();
        }
    }

    void QuicEndpoint::Run(std::function<void()> fn)
    {
        if (!active_) {
            return;
        }
        if (OnNetworkThread()) {
            fn();
            return;
        }

        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        Post([&] {
            fn();
            std::lock_guard lock(mutex);
            done = true;
            cv.notify_one();
        });
        std::unique_lock lock(mutex);
        cv.wait(lock, [&] { return done || !active_; });
    }

    void QuicEndpoint::Release(uint64_t id)
    {
        std::lock_guard lock(connections_mutex_);
        std::erase_if(connections_, [&](const auto& item) { return item.first == id; });
    }

    std::shared_ptr<QuicConnection> QuicEndpoint::Adopt(picoquic_cnx_t* cnx)
    {
        std::shared_ptr<QuicConnection> connection;
        {
            std::lock_guard lock(connections_mutex_);
            for (const auto& [id, existing] : connections_) {
                (void)id;
                if (existing && existing->cnx_ == cnx) {
                    return nullptr;
                }
            }
            connection = std::shared_ptr<QuicConnection>(new QuicConnection(shared_from_this(), cnx, next_id_++));
            connections_.emplace_back(connection->Id(), connection);
        }

        picoquic_set_callback(cnx, &QuicConnection::Callback, connection.get());
        picoquic_enable_keep_alive(cnx, kIdleTimeoutMs * 500);
        picoquic_set_feedback_loss_notification(cnx, 1);
        if (on_accept_) {
            on_accept_(connection);
        }
        return connection;
    }

    int QuicEndpoint::ServerCallback(picoquic_cnx_t* cnx,
                                     uint64_t,
                                     uint8_t*,
                                     size_t,
                                     picoquic_call_back_event_t event,
                                     void* callback_ctx,
                                     void*)
    {
        auto* endpoint = static_cast<QuicEndpoint*>(callback_ctx);
        if (endpoint == nullptr) {
            return 0;
        }
        if (event == picoquic_callback_almost_ready || event == picoquic_callback_ready) {
            if (auto created = endpoint->Adopt(cnx); created && event == picoquic_callback_ready) {
                created->OnEvent(0, nullptr, 0, picoquic_callback_ready);
            }
        }
        return 0;
    }

    int QuicEndpoint::LoopCallback(picoquic_quic_t*,
                                   picoquic_packet_loop_cb_enum cb_mode,
                                   void* callback_ctx,
                                   void*)
    {
        auto* endpoint = static_cast<QuicEndpoint*>(callback_ctx);
        if (endpoint == nullptr) {
            return 0;
        }
        if (cb_mode == picoquic_packet_loop_ready) {
            endpoint->network_thread_id_ = std::this_thread::get_id();
        } else if (cb_mode == picoquic_packet_loop_wake_up) {
            endpoint->Drain();
        }
        return 0;
    }

    std::shared_ptr<QuicConnection> QuicEndpoint::Dial(const std::string& cert_file,
                                                       const std::string& key_file,
                                                       const std::string& host,
                                                       uint16_t port,
                                                       QuicConnection::Handlers handlers)
    {
        auto endpoint = std::shared_ptr<QuicEndpoint>(new QuicEndpoint(cert_file, key_file, 0, false, {}));
        endpoint->StartThread();

        sockaddr_storage address{};
        int is_name = 0;
        if (picoquic_get_server_address(host.c_str(), port, &address, &is_name) != 0 || address.ss_family == 0) {
            throw std::runtime_error("Failed to resolve peering peer " + host);
        }
        const char* sni = is_name ? host.c_str() : "localhost";

        std::shared_ptr<QuicConnection> connection;

        endpoint->Run([&] {
            picoquic_cnx_t* cnx = picoquic_create_cnx(endpoint->quic_,
                                                      picoquic_null_connection_id,
                                                      picoquic_null_connection_id,
                                                      reinterpret_cast<struct sockaddr*>(&address),
                                                      picoquic_current_time(),
                                                      0,
                                                      sni,
                                                      kAlpn,
                                                      1);
            if (cnx == nullptr) {
                return;
            }

            connection = std::shared_ptr<QuicConnection>(new QuicConnection(endpoint, cnx, endpoint->next_id_++));
            {
                std::lock_guard lock(endpoint->connections_mutex_);
                endpoint->connections_.emplace_back(connection->Id(), connection);
            }

            connection->SetHandlers(handlers);
            picoquic_set_callback(cnx, &QuicConnection::Callback, connection.get());
            picoquic_enable_keep_alive(cnx, kIdleTimeoutMs * 500);
            picoquic_set_feedback_loss_notification(cnx, 1);
        });

        return connection;
    }

} // namespace moq::peering
