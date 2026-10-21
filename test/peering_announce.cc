#include <doctest/doctest.h>

#include "peering/messages/announce_info.h"

using namespace std::string_literals;

TEST_CASE("Serialize Announce Info")
{
    using namespace moq::peering;

    AnnounceInfo announce_info;
    announce_info.track.source_node_id = 0xff00aabbcc;

    announce_info.track.name_space = NameSpace{ "abc"s, "12345"s, "third tuple"s, "now the final tuple"s };
    announce_info.track.name = std::vector<uint8_t>{ 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    announce_info.track.fullname_hash = 0x9876543210;

    auto net_data = announce_info.Serialize(false);

    CHECK_EQ(net_data.size(), 75);
    CHECK_EQ(announce_info.SizeBytes(), 75);

    AnnounceInfo decoded_ai(net_data);

    CHECK_EQ(announce_info.track.source_node_id, decoded_ai.track.source_node_id);

    CHECK(announce_info.track.name_space == decoded_ai.track.name_space);
    CHECK(announce_info.track.name == decoded_ai.track.name);
    CHECK_EQ(announce_info.track.fullname_hash, decoded_ai.track.fullname_hash);
}
