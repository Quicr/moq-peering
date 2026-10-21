// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause

#include "info_base.h"

#include <stdexcept>

namespace moq::peering {
    namespace {
        template<typename T>
        T Read(std::span<const uint8_t>::iterator& it, const std::span<const uint8_t>::iterator end)
        {
            if (static_cast<std::size_t>(end - it) < sizeof(T)) {
                throw std::out_of_range("Subscribe info truncated");
            }

            const T value = ValueOf<T>({ it, it + static_cast<std::ptrdiff_t>(sizeof(T)) });
            it += sizeof(T);
            return value;
        }

        template<typename T>
        void Append(std::vector<uint8_t>& data, const T& value)
        {
            const auto bytes = BytesOf(value);
            data.insert(data.end(), bytes.rbegin(), bytes.rend());
        }

        uint32_t NameSize(const TrackIdentity& track)
        {
            return 1 + sizeof(uint16_t) * static_cast<uint32_t>(track.name_space.GetEntries().size()) +
                   static_cast<uint32_t>(track.name_space.size()) + sizeof(uint16_t) +
                   static_cast<uint32_t>(track.name.size());
        }

        void AppendName(std::vector<uint8_t>& data, const TrackIdentity& track)
        {
            const auto& entries = track.name_space.GetEntries();
            data.push_back(static_cast<uint8_t>(entries.size()));
            for (const auto& entry : entries) {
                Append(data, static_cast<uint16_t>(entry.size()));
                data.insert(data.end(), entry.begin(), entry.end());
            }

            Append(data, static_cast<uint16_t>(track.name.size()));
            if (!track.name.empty()) {
                data.insert(data.end(), track.name.begin(), track.name.end());
            }
        }

        void WriteHeader(std::vector<uint8_t>& data, MsgType type, uint32_t size)
        {
            data.reserve(kCommonHeadersSize + size);
            data.push_back(kProtocolVersion);
            Append(data, static_cast<uint16_t>(type));
            Append(data, size);
        }
    }

    template<>
    SubscribeInfo::InfoBase(std::span<const uint8_t> serialized_data)
    {
        auto it = serialized_data.begin();
        const auto end = serialized_data.end();

        details.seq = Read<uint16_t>(it, end);
        track.source_node_id = Read<uint64_t>(it, end);

        details.track_hash.track_namespace_hash = Read<uint64_t>(it, end);
        details.track_hash.track_name_hash = Read<uint64_t>(it, end);
        details.track_hash.track_fullname_hash = Read<uint64_t>(it, end);
        track.fullname_hash = details.track_hash.track_fullname_hash;

        details.priority = Read<uint8_t>(it, end);
        details.delivery_timeout = Read<uint64_t>(it, end);
        details.expires = Read<uint64_t>(it, end);
        details.forward = Read<uint64_t>(it, end);

        if (Read<uint8_t>(it, end) != 0) {
            details.new_group_request_id = Read<uint64_t>(it, end);
        }

        const auto num_entries = Read<uint8_t>(it, end);
        std::vector<std::span<const uint8_t>> entries;
        entries.reserve(num_entries);

        for (uint8_t i = 0; i < num_entries; ++i) {
            const auto len = Read<uint16_t>(it, end);
            if (static_cast<std::size_t>(end - it) < len) {
                throw std::out_of_range("Subscribe namespace entry exceeds serialized data");
            }

            entries.emplace_back(it, it + len);
            it += len;
        }

        track.name_space = NameSpace(std::span<const std::span<const uint8_t>>{ entries });

        const auto name_size = Read<uint16_t>(it, end);
        if (static_cast<std::size_t>(end - it) < name_size) {
            throw std::out_of_range("Subscribe name exceeds serialized data");
        }

        if (name_size != 0) {
            track.name.assign(it, it + name_size);
        }
    }

    template<>
    uint32_t SubscribeInfo::SizeBytes() const
    {
        return sizeof(details.seq) + sizeof(track.source_node_id) + 24 /* namespace, name, and full name hashes */
               + sizeof(details.priority) + sizeof(details.delivery_timeout) + sizeof(details.expires) +
               sizeof(details.forward) + 1 /* new group present */
               + (details.new_group_request_id.has_value() ? sizeof(uint64_t) : 0) + NameSize(track);
    }

    template<>
    std::vector<uint8_t> SubscribeInfo::Serialize(bool include_common_header, bool withdraw, bool is_origin)
    {
        if (is_origin) {
            if (details.seq < 0xFFFF)
                details.seq++;
            else
                details.seq = 0;
        }

        std::vector<uint8_t> data;
        const auto size = SizeBytes();
        if (include_common_header) {
            WriteHeader(data, withdraw ? MsgType::kSubscribeInfoWithdrawn : MsgType::kSubscribeInfoAdvertised, size);
        } else {
            data.reserve(size);
        }

        Append(data, details.seq);
        Append(data, track.source_node_id);
        Append(data, details.track_hash.track_namespace_hash);
        Append(data, details.track_hash.track_name_hash);
        Append(data, details.track_hash.track_fullname_hash);
        Append(data, details.priority);
        Append(data, details.delivery_timeout);
        Append(data, details.expires);
        Append(data, details.forward);
        Append(data, static_cast<uint8_t>(details.new_group_request_id.has_value() ? 1 : 0));
        if (details.new_group_request_id.has_value()) {
            Append(data, *details.new_group_request_id);
        }
        AppendName(data, track);
        return data;
    }

    template<>
    AnnounceInfo::InfoBase(std::span<const uint8_t> serialized_data)
    {
        auto it = serialized_data.begin();

        track.source_node_id = ValueOf<uint64_t>({ it, it + 8 });
        it += 8;

        track.fullname_hash = ValueOf<uint64_t>({ it, it + 8 });
        it += 8;

        const uint8_t num_entries = *it;
        ++it;

        std::vector<std::span<const uint8_t>> entries;
        entries.reserve(num_entries);

        for (int i = 0; i < num_entries; i++) {
            const uint16_t len = ValueOf<uint16_t>({ it, it + 2 });
            it += 2;

            entries.emplace_back(it, it + len);
            it += len;
        }

        track.name_space = NameSpace(entries);

        const uint16_t name_size = ValueOf<uint16_t>({ it, it + 2 });
        it += 2;

        if (name_size) {
            track.name.assign(it, it + name_size);
            it += name_size;
        }

        details.flags = *it++;
    }

    template<>
    uint32_t AnnounceInfo::SizeBytes() const
    {
        return sizeof(track.source_node_id) + sizeof(track.fullname_hash) + NameSize(track) + 1;
    }

    template<>
    std::vector<uint8_t> AnnounceInfo::Serialize(bool include_common_header, bool withdraw) const
    {
        std::vector<uint8_t> data;
        const auto size = SizeBytes();
        if (include_common_header) {
            WriteHeader(data, withdraw ? MsgType::kAnnounceInfoWithdrawn : MsgType::kAnnounceInfoAdvertised, size);
        } else {
            data.reserve(size);
        }

        Append(data, track.source_node_id);
        Append(data, track.fullname_hash);
        AppendName(data, track);
        data.push_back(details.flags);
        return data;
    }
}
