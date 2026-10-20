// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include "cityhash.h"

#include <moq/peering/types.h>

#include <cstdint>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace moq::peering {

    /**
     * @brief Namespace tuples, hashed the same way as a MoQ track namespace
     */
    class NameSpace
    {
      public:
        NameSpace() = default;

        explicit NameSpace(const std::vector<std::vector<uint8_t>>& entries) { Assign(entries); }

        explicit NameSpace(std::span<const std::span<const uint8_t>> entries)
        {
            std::vector<std::vector<uint8_t>> owned;
            owned.reserve(entries.size());
            for (const auto& entry : entries) {
                owned.emplace_back(entry.begin(), entry.end());
            }
            Assign(owned);
        }

        template<typename... S, std::enable_if_t<std::is_same_v<std::common_type_t<S...>, std::string>, bool> = true>
        explicit NameSpace(S&&... entries)
        {
            std::vector<std::vector<uint8_t>> owned;
            owned.reserve(sizeof...(S));
            (owned.emplace_back(entries.begin(), entries.end()), ...);
            Assign(std::move(owned));
        }

        NameSpace(const NameSpace& other) { Assign(other.entries_); }
        NameSpace& operator=(const NameSpace& other)
        {
            if (this != &other) {
                Assign(other.entries_);
            }
            return *this;
        }
        NameSpace(NameSpace&& other) noexcept { Assign(other.entries_); }
        NameSpace& operator=(NameSpace&& other) noexcept
        {
            if (this != &other) {
                Assign(other.entries_);
            }
            return *this;
        }

        const std::vector<std::span<const uint8_t>>& GetEntries() const noexcept { return spans_; }
        const std::vector<uint64_t>& GetHashes() const noexcept { return hashes_; }
        std::size_t size() const noexcept { return bytes_.size(); }

        /// Hash of the concatenated tuples. Empty is the CityHash of zero bytes.
        uint64_t Hash() const { return hash(std::span<const uint8_t>(bytes_.data(), bytes_.size())); }

        friend bool operator==(const NameSpace& lhs, const NameSpace& rhs) noexcept
        {
            return lhs.entries_ == rhs.entries_;
        }

        bool HasSamePrefix(const NameSpace& other) const noexcept
        {
            const auto prefix_size = std::min(hashes_.size(), other.hashes_.size());
            for (std::size_t i = 0; i < prefix_size; ++i) {
                if (hashes_[i] != other.hashes_[i]) {
                    return false;
                }
            }
            return true;
        }

      private:
        void Assign(const std::vector<std::vector<uint8_t>>& entries)
        {
            entries_ = entries;
            bytes_.clear();
            spans_.clear();
            hashes_.clear();
            spans_.reserve(entries_.size());
            hashes_.reserve(entries_.size());
            for (const auto& entry : entries_) {
                bytes_.insert(bytes_.end(), entry.begin(), entry.end());
            }
            std::size_t offset = 0;
            for (const auto& entry : entries_) {
                spans_.emplace_back(bytes_.data() + offset, entry.size());
                hashes_.push_back(hash(std::span<const uint8_t>(entry.data(), entry.size())));
                offset += entry.size();
            }
        }

        std::vector<std::vector<uint8_t>> entries_;
        std::vector<uint8_t> bytes_;
        std::vector<std::span<const uint8_t>> spans_;
        std::vector<uint64_t> hashes_;
    };

    struct FullName
    {
        NameSpace name_space;
        std::vector<uint8_t> name;
    };

    struct TrackHash
    {
        uint64_t track_namespace_hash{ 0 };
        uint64_t track_name_hash{ 0 };
        uint64_t track_fullname_hash{ 0 };

        TrackHash() = default;

        TrackHash(uint64_t name_space, uint64_t name) noexcept
          : track_namespace_hash{ name_space }
          , track_name_hash{ name }
        {
            hash_combine(track_fullname_hash, track_namespace_hash);
            hash_combine(track_fullname_hash, track_name_hash);
        }

        TrackHash(const NameSpace& name_space, std::span<const uint8_t> name) noexcept
          : TrackHash(name_space.Hash(), hash(name))
        {
        }

        TrackHash(const FullName& full) noexcept
          : TrackHash(full.name_space, full.name)
        {
        }

        explicit TrackHash(const TrackName& name) noexcept
          : TrackHash(NameSpace(name.name_space), std::span<const uint8_t>(name.name.data(), name.name.size()))
        {
        }
    };

} // namespace moq::peering
