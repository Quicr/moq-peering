// SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include "node_info.h"
#include "peering/common.h"
#include "peering/name.h"

#include <optional>
#include <span>
#include <vector>

namespace moq::peering {

    /**
     * @brief Track identity carried by both subscribe and announce
     */
    struct TrackIdentity
    {
        NodeIdValueType source_node_id{ 0 };
        NameSpace name_space;
        std::vector<uint8_t> name;
        uint64_t fullname_hash{ 0 };
    };

    /**
     * @brief Fields that exist only on a subscribe
     *
     * @details seq is an incremental sequence. A smaller value than the current one can be ignored, unless it wraps
     *      through zero. The three track hashes and the subscribe parameters are encoded as fixed-width integers.
     *      new_group_request_id is preceded by a presence byte and omitted when unset.
     */
    struct SubscribeDetails
    {
        uint16_t seq{ 0 };
        TrackHash track_hash;
        uint8_t priority{ 0 };
        uint64_t delivery_timeout{ 0 }; ///< Milliseconds
        uint64_t expires{ 0 };          ///< Milliseconds
        uint64_t forward{ 0 };          ///< Non-zero forwards data, zero pauses it
        std::optional<uint64_t> new_group_request_id;
    };

    /**
     * @brief Fields that exist only on an announce
     *
     * @details Bit 0 of flags selects the announcement. Set means a namespace, clear means a track.
     */
    struct AnnounceDetails
    {
        uint8_t flags{ 0 };
    };

    /**
     * @brief One subscribe or one announce
     *
     * @details The track identity is the same for both kinds. Details and the wire encoding stay with the kind.
     *      Subscribe bytes are sequence, node, three hashes, parameters, then the name. Announce bytes are node,
     *      one hash, the name, then flags.
     */
    template<typename Details>
    struct InfoBase
    {
        TrackIdentity track;
        Details details;

        InfoBase() = default;
        explicit InfoBase(std::span<const uint8_t> serialized_data);

        uint32_t SizeBytes() const;

        std::vector<uint8_t> Serialize(bool include_common_header, bool withdraw = false) const;
        std::vector<uint8_t> Serialize(bool include_common_header, bool withdraw, bool is_origin);
    };

    using SubscribeInfo = InfoBase<SubscribeDetails>;
    using AnnounceInfo = InfoBase<AnnounceDetails>;

    template<>
    SubscribeInfo::InfoBase(std::span<const uint8_t> serialized_data);
    template<>
    uint32_t SubscribeInfo::SizeBytes() const;
    template<>
    std::vector<uint8_t> SubscribeInfo::Serialize(bool include_common_header, bool withdraw, bool is_origin);

    template<>
    AnnounceInfo::InfoBase(std::span<const uint8_t> serialized_data);
    template<>
    uint32_t AnnounceInfo::SizeBytes() const;
    template<>
    std::vector<uint8_t> AnnounceInfo::Serialize(bool include_common_header, bool withdraw) const;

} // namespace moq::peering
