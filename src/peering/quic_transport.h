// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <picoquic.h>
#include <picoquic_packet_loop.h>

namespace moq::peering {

    enum class StreamClose : uint8_t
    {
        kFin = 0,
        kReset,
        kStopSending,
    };

    struct SendFlags
    {
        bool reliable{ false };
        bool close_stream{ false };
    };

    struct QuicStream
    {
        uint64_t id{ 0 };
        bool bidirectional{ false };
    };

    class QuicEndpoint;

    /**
     * @brief One QUIC connection
     *
     * @details picoquic calls run on the endpoint network thread. Methods called from other threads
     *      are posted there.
     */
    class QuicConnection : public std::enable_shared_from_this<QuicConnection>
    {
      public:
        struct Handlers
        {
            std::function<void()> on_ready;
            std::function<void()> on_closed;
            std::function<void(uint64_t stream_id, bool bidirectional, std::vector<uint8_t> data, bool fin)> on_stream;
            std::function<void(std::vector<uint8_t> data)> on_datagram;
            std::function<void(uint64_t stream_id, StreamClose how)> on_stream_closed;
        };

        uint64_t Id() const { return id_; }
        std::pair<std::string, uint16_t> PeerAddress() const;
        uint64_t RttUs() const;

        void SetHandlers(Handlers handlers);
        std::shared_ptr<QuicStream> OpenBidirectional(uint8_t priority);
        std::shared_ptr<QuicStream> OpenUnidirectional(uint8_t priority);
        void Send(uint64_t stream_id, std::span<const uint8_t> data, bool fin);
        void SendDatagram(std::span<const uint8_t> data);
        void Reset(uint64_t stream_id);
        void StopSending(uint64_t stream_id);
        void Close();
        // Join this connection's packet loop. Client dials own the loop; the server loop is shared.
        void StopEndpoint();
        void Start();

      private:
        friend class QuicEndpoint;

        QuicConnection(std::shared_ptr<QuicEndpoint> endpoint, picoquic_cnx_t* cnx, uint64_t id);

        static int Callback(picoquic_cnx_t* cnx,
                            uint64_t stream_id,
                            uint8_t* bytes,
                            size_t length,
                            picoquic_call_back_event_t event,
                            void* callback_ctx,
                            void* stream_ctx);

        int OnEvent(uint64_t stream_id, uint8_t* bytes, size_t length, picoquic_call_back_event_t event);
        void Run(std::function<void()> fn);
        // Runs inline on this connection's network thread. Otherwise queues the work and returns.
        // Waiting here deadlocks when two relays forward to each other from their QUIC callbacks.
        void Dispatch(std::function<void()> fn);

        std::shared_ptr<QuicEndpoint> endpoint_;
        picoquic_cnx_t* cnx_{ nullptr };
        uint64_t id_{ 0 };
        Handlers handlers_;
        bool closing_{ false };
        bool closed_notified_{ false };
        mutable std::mutex handler_mutex_;
    };

    /**
     * @brief picoquic instance and its packet loop
     *
     * @details A server endpoint accepts many connections. A client endpoint dials one peer.
     *      Certificate and key are file paths. They are never embedded.
     */
    class QuicEndpoint : public std::enable_shared_from_this<QuicEndpoint>
    {
      public:
        using AcceptFn = std::function<void(const std::shared_ptr<QuicConnection>&)>;

        static std::shared_ptr<QuicEndpoint> Listen(const std::string& cert_file,
                                                    const std::string& key_file,
                                                    uint16_t port,
                                                    AcceptFn on_accept);

        static std::shared_ptr<QuicConnection> Dial(const std::string& cert_file,
                                                    const std::string& key_file,
                                                    const std::string& host,
                                                    uint16_t port,
                                                    QuicConnection::Handlers handlers);

        void Shutdown();
        ~QuicEndpoint();

        bool OnNetworkThread() const { return std::this_thread::get_id() == network_thread_id_; }

      private:
        friend class QuicConnection;

        QuicEndpoint(std::string cert_file, std::string key_file, uint16_t port, bool server, AcceptFn on_accept);

        void StartThread();
        void Drain();
        void Post(std::function<void()> fn);
        void Run(std::function<void()> fn);
        std::shared_ptr<QuicConnection> Adopt(picoquic_cnx_t* cnx);
        void Release(uint64_t id);

        static int LoopCallback(picoquic_quic_t* quic,
                                picoquic_packet_loop_cb_enum cb_mode,
                                void* callback_ctx,
                                void* callback_argv);
        static int ServerCallback(picoquic_cnx_t* cnx,
                                  uint64_t stream_id,
                                  uint8_t* bytes,
                                  size_t length,
                                  picoquic_call_back_event_t event,
                                  void* callback_ctx,
                                  void* stream_ctx);

        std::string cert_file_;
        std::string key_file_;
        uint16_t port_{ 0 };
        bool server_{ false };
        AcceptFn on_accept_;

        picoquic_quic_t* quic_{ nullptr };
        picoquic_network_thread_ctx_t* thread_{ nullptr };
        picoquic_packet_loop_param_t loop_params_{};
        std::thread::id network_thread_id_{};
        bool active_{ false };

        std::mutex queue_mutex_;
        std::vector<std::function<void()>> queue_;
        std::mutex connections_mutex_;
        std::vector<std::pair<uint64_t, std::shared_ptr<QuicConnection>>> connections_;
    };

} // namespace moq::peering
