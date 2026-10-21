#include <doctest/doctest.h>

#include "peering/messages/subscribe_info.h"

#include <span>
#include <stdexcept>
#include <string>

namespace {
    moq::peering::SubscribeInfo MakeSubscribeInfo(bool with_new_group)
    {
        using namespace moq::peering;

        SubscribeInfo subscribe_info;
        subscribe_info.track.source_node_id = 0xff00aabbcc;

        TrackHash track_hash;
        track_hash.track_name_hash = 0x9000;
        track_hash.track_namespace_hash = 0xaabbcc;
        track_hash.track_fullname_hash = 0x1234567;
        subscribe_info.details.track_hash = track_hash;
        subscribe_info.track.fullname_hash = track_hash.track_fullname_hash;

        subscribe_info.track.name_space = NameSpace(std::string("namespace"));
        subscribe_info.track.name = { 't', 'r', 'a', 'c', 'k' };
        subscribe_info.details.priority = 10;
        subscribe_info.details.delivery_timeout = 5000;
        subscribe_info.details.expires = 1000;
        subscribe_info.details.forward = 1;
        if (with_new_group) {
            subscribe_info.details.new_group_request_id = 42;
        }

        return subscribe_info;
    }

    void CheckRoundTrip(moq::peering::SubscribeInfo& subscribe_info)
    {
        using namespace moq::peering;

        auto net_data = subscribe_info.Serialize(false, false, true);

        CHECK_EQ(net_data.size(), subscribe_info.SizeBytes());
        CHECK_EQ(subscribe_info.details.seq, 1);

        SubscribeInfo decoded_si(net_data);

        CHECK_EQ(subscribe_info.details.seq, decoded_si.details.seq);
        CHECK_EQ(subscribe_info.track.source_node_id, decoded_si.track.source_node_id);
        CHECK_EQ(subscribe_info.details.track_hash.track_namespace_hash,
                 decoded_si.details.track_hash.track_namespace_hash);
        CHECK_EQ(subscribe_info.details.track_hash.track_name_hash, decoded_si.details.track_hash.track_name_hash);
        CHECK_EQ(subscribe_info.details.track_hash.track_fullname_hash,
                 decoded_si.details.track_hash.track_fullname_hash);
        CHECK_EQ(subscribe_info.track.name_space, decoded_si.track.name_space);
        CHECK_EQ(subscribe_info.track.name, decoded_si.track.name);
        CHECK_EQ(subscribe_info.details.priority, decoded_si.details.priority);
        CHECK_EQ(subscribe_info.details.delivery_timeout, decoded_si.details.delivery_timeout);
        CHECK_EQ(subscribe_info.details.expires, decoded_si.details.expires);
        CHECK_EQ(subscribe_info.details.forward, decoded_si.details.forward);
        CHECK_EQ(subscribe_info.details.new_group_request_id, decoded_si.details.new_group_request_id);
    }
}

TEST_CASE("Serialize Subscribe Info")
{
    auto subscribe_info = MakeSubscribeInfo(true);
    CheckRoundTrip(subscribe_info);
}

TEST_CASE("Serialize Subscribe Info without new group request")
{
    auto subscribe_info = MakeSubscribeInfo(false);
    CheckRoundTrip(subscribe_info);
    CHECK_FALSE(subscribe_info.details.new_group_request_id.has_value());
}

TEST_CASE("Subscribe Info truncated input throws")
{
    using namespace moq::peering;
    const std::vector<uint8_t> truncated{ 0x00, 0x01 };
    CHECK_THROWS_AS(SubscribeInfo(std::span<const uint8_t>{ truncated }), std::out_of_range);
}
