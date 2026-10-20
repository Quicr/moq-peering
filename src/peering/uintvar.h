// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include "cityhash.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace moq::peering {

    // QUIC-style variable-length integer, matching the encoding previously taken from libquicr.
    class UintVar
    {
      public:
        constexpr UintVar(uint64_t value) noexcept
          : be_value_{ 0 }
        {
            const auto bits = std::bit_width(value);
            const std::size_t length = std::min<std::size_t>(kMaxEncodedSize, bits == 0 ? 1 : (bits + 6) / 7);

            if (length == kMaxEncodedSize) {
                const auto bytes = std::bit_cast<std::array<std::uint8_t, sizeof(value)>>(SwapBytes(value));
                std::copy(bytes.begin(), bytes.end(), std::next(be_value_.begin()));
                be_value_.front() = 0xFF;
                return;
            }

            const auto value_be = SwapBytes(value << ((sizeof(value) - length) * 8));
            const auto bytes = std::bit_cast<std::array<std::uint8_t, sizeof(value)>>(value_be);
            std::copy(bytes.begin(), bytes.end(), be_value_.begin());
            const auto prefix = length == 1 ? 0u : static_cast<std::uint8_t>(0xFFu << (kMaxEncodedSize - length));
            be_value_.front() |= static_cast<std::uint8_t>(prefix);
        }

        explicit UintVar(std::span<const std::uint8_t> bytes)
          : be_value_{ 0 }
        {
            if (bytes.empty() || bytes.size() < Size(bytes.front())) {
                throw std::invalid_argument("Invalid bytes for uintvar");
            }
            std::copy_n(bytes.data(), Size(bytes.front()), be_value_.begin());
        }

        constexpr std::uint64_t Get() const noexcept
        {
            const auto length = Size();
            const auto value_bits = length == kMaxEncodedSize ? 0 : 8 - length;
            const auto mask = value_bits == 0 ? 0 : static_cast<std::uint8_t>((1u << value_bits) - 1);
            std::uint64_t value = be_value_.front() & mask;
            for (std::size_t i = 1; i < length; ++i) {
                value = (value << 8) | be_value_[i];
            }
            return value;
        }

        static constexpr std::size_t Size(uint8_t msb_bytes) noexcept
        {
            const auto leading_ones = std::countl_one(msb_bytes);
            return leading_ones == 8 ? kMaxEncodedSize : leading_ones + 1;
        }

        constexpr std::size_t Size() const noexcept { return UintVar::Size(be_value_.front()); }

        constexpr const std::uint8_t* data() const noexcept { return be_value_.data(); }
        constexpr std::size_t size() const noexcept { return Size(); }
        constexpr auto begin() const noexcept { return data(); }
        constexpr auto end() const noexcept { return data() + Size(); }

        explicit constexpr operator uint64_t() const noexcept { return Get(); }

      private:
        static constexpr std::size_t kMaxEncodedSize = sizeof(std::uint64_t) + 1;
        std::array<std::uint8_t, kMaxEncodedSize> be_value_;
    };

} // namespace moq::peering
