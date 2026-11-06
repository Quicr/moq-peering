
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <random>

#include "peering/forwarding_base.h"

using namespace std::string_literals;
using moq::peering::FullName;
using moq::peering::NameSpace;

std::vector<FullName>
GenerateFullTrackNames(int count)
{
    std::srand(std::time({}));
    std::vector<FullName> full_names;

    for (int i = 0; i < count; i++) {
        const int rvalue = std::rand();
        const auto name = std::to_string(rvalue);
        full_names.push_back({ NameSpace{ "first"s, "second"s, "third"s, "final namespace tuple"s, "r=" + name },
                               { name.begin(), name.end() } });
    }

    return full_names;
}

TEST_CASE("Add/Remove Announces")
{
    using namespace moq::peering;

    const auto full_names = GenerateFullTrackNames(30);
    std::shared_ptr<ForwardingBase> ib = std::make_shared<ForwardingBase>();

    // Add to info base
    for (const auto& fn : full_names) {
        const auto fn_hash = TrackHash(fn);
        AnnounceInfo ai;
        ai.track.fullname_hash = fn_hash.track_fullname_hash;
        ai.track.name_space = fn.name_space, ai.track.name = fn.name;
        ai.track.source_node_id = 0x12345678;

        ib->AddAnnounce(ai);
    }

    // With 30 announces each with a unique full namespace path, we expect 30*5=150 prefix hash keys
    // (each announce has 5 namespace levels, so 5 prefix paths)
    // But after removing duplicates through the set, we get 34 unique prefix hashes
    CHECK_EQ(ib->prefix_lookup_announces_.size(), 34);
    // Verify entries exist
    int total_hashes = 0;
    for (const auto& [_, v] : ib->prefix_lookup_announces_) {
        total_hashes += v.size();
    }
    CHECK_GT(total_hashes, 0);

    // Remove first and last 5
    for (int i = 0; i < 5; i++) {
        AnnounceInfo ai;
        ai.track.source_node_id = 0x12345678;

        auto fn = full_names.at(i);
        auto fn_hash = TrackHash(fn);

        ai.track.fullname_hash = fn_hash.track_fullname_hash;
        ai.track.name_space = fn.name_space, ai.track.name = fn.name;

        ib->RemoveAnnounce(ai);

        fn = full_names.at(full_names.size() - (i + 1));
        fn_hash = TrackHash(fn);

        ai.track.fullname_hash = fn_hash.track_fullname_hash;
        ai.track.name_space = fn.name_space, ai.track.name = fn.name;

        ib->RemoveAnnounce(ai);
    }

    // After removing 10 announces (first 5 and last 5), we should have 20 left
    // Prefix lookup should still have entries for those 20
    CHECK_GT(ib->prefix_lookup_announces_.size(), 0);
    int total_remaining = 0;
    for (const auto& [_, v] : ib->prefix_lookup_announces_) {
        total_remaining += v.size();
    }
    // Should have at most 20 announces referenced
    CHECK_LE(total_remaining, 20 * 5); // Each announce creates up to 5 prefix hashes

    // Remove from info base
    for (const auto& fn : full_names) {
        const auto fn_hash = TrackHash(fn);
        AnnounceInfo ai;
        ai.track.fullname_hash = fn_hash.track_fullname_hash;
        ai.track.name_space = fn.name_space, ai.track.name = fn.name;
        ai.track.source_node_id = 0x12345678;

        ib->RemoveAnnounce(ai);
    }

    CHECK(ib->prefix_lookup_announces_.empty());
}

TEST_CASE("Prefix match announces")
{
    using namespace moq::peering;

    const auto full_names = GenerateFullTrackNames(30);
    std::shared_ptr<ForwardingBase> ib = std::make_shared<ForwardingBase>();

    // Add to info base
    for (const auto& fn : full_names) {
        const auto fn_hash = TrackHash(fn);
        AnnounceInfo ai;
        ai.track.fullname_hash = fn_hash.track_fullname_hash;
        ai.track.name_space = fn.name_space, ai.track.name = fn.name;
        ai.track.source_node_id = 0x12345678;

        ib->AddAnnounce(ai);
    }

    const auto ns1 = NameSpace{ "first"s, "second"s, "third"s, "final namespace tuple"s, "invalid"s };
    const auto ns2 = NameSpace{ "first"s, "second"s, "third"s };
    const auto ns3 = NameSpace{ "first"s, "second"s };
    const auto ns4 = NameSpace{ "first"s };

    auto result = ib->GetAnnounceIds(ns1, {}, false);
    CHECK_EQ(result.size(), 0);

    result = ib->GetAnnounceIds(ns2, {}, false);
    CHECK_EQ(result.size(), 1);

    result = ib->GetAnnounceIds(ns3, {}, false);
    CHECK_EQ(result.size(), 1);

    result = ib->GetAnnounceIds(ns4, {}, false);
    CHECK_EQ(result.size(), 1);
}

namespace {
    moq::peering::SubscribeInfo Subscribe(std::uint64_t hash, moq::peering::NodeIdValueType source, std::uint16_t seq)
    {
        moq::peering::SubscribeInfo info;
        info.track.fullname_hash = hash;
        info.track.source_node_id = source;
        info.details.seq = seq;
        return info;
    }
}

TEST_CASE("Subscribe sequence retention")
{
    using namespace moq::peering;
    using clock = std::chrono::steady_clock;

    ForwardingBase base;
    const std::uint64_t hash = 0xabc;
    const NodeIdValueType source = 42;
    const auto now = clock::now();

    CHECK(base.AddSubscribe(Subscribe(hash, source, 5)));
    CHECK_FALSE(base.AddSubscribe(Subscribe(hash, source, 5)));
    CHECK_FALSE(base.AddSubscribe(Subscribe(hash, source, 4)));
    CHECK(base.GetSubscribe(hash, source).has_value());

    CHECK_FALSE(base.RemoveSubscribe(Subscribe(hash, source, 4)));
    CHECK_FALSE(base.RemoveSubscribe(Subscribe(hash, source, 5)));
    CHECK(base.GetSubscribe(hash, source).has_value());

    CHECK(base.RemoveSubscribe(Subscribe(hash, source, 6)));
    CHECK_FALSE(base.GetSubscribe(hash, source).has_value());
    CHECK(base.StoredSequence(hash, source) == std::optional<std::uint16_t>(6));
    CHECK_FALSE(base.AddSubscribe(Subscribe(hash, source, 6)));
    CHECK(base.AddSubscribe(Subscribe(hash, source, 7)));

    CHECK(base.AddSubscribe(Subscribe(0xdef, source, 65535)));
    CHECK(base.AddSubscribe(Subscribe(0xdef, source, 0)));
    CHECK_FALSE(base.AddSubscribe(Subscribe(0xdef, source, 65535)));

    base.NoteSourceUnreachable(source, now);
    CHECK_FALSE(base.AddSubscribe(Subscribe(hash, source, 1)));
    CHECK(base.StoredSequence(hash, source) == std::optional<std::uint16_t>(7));
    CHECK(base.AddSubscribe(Subscribe(hash, source, 8)));
    base.NoteSourceReachable(source);
    base.ExpireSubscribeSequences(now + std::chrono::seconds(60));
    CHECK(base.StoredSequence(hash, source) == std::optional<std::uint16_t>(8));

    base.NoteSourceUnreachable(source, now);
    base.NoteSourceReachable(source);
    base.ExpireSubscribeSequences(now + std::chrono::seconds(60));
    CHECK_FALSE(base.StoredSequence(hash, source).has_value());
    CHECK(base.AddSubscribe(Subscribe(hash, source, 1)));
    CHECK(base.StoredSequence(hash, source) == std::optional<std::uint16_t>(1));

    CHECK(base.RemoveSubscribe(Subscribe(hash, source, 1), true));
    CHECK_FALSE(base.GetSubscribe(hash, source).has_value());
    CHECK(base.StoredSequence(hash, source) == std::optional<std::uint16_t>(1));
    CHECK(base.AddSubscribe(Subscribe(hash, source, 1)));
    CHECK(base.GetSubscribe(hash, source).has_value());
    CHECK(base.AddSubscribe(Subscribe(hash, source, 2)));

    {
        // A reset to epoch 1 sequence 0 is greater than retained epoch 0 sequence 65535 by the
        // sequence ring alone. The epoch keeps it from being accepted or cancelling retention.
        const NodeIdValueType other = 99;
        const std::uint64_t wrap = 0xe01;
        CHECK(base.AddSubscribe(Subscribe(wrap, other, 65535)));
        auto reset = Subscribe(wrap, other, 0);
        reset.details.epoch = 1;
        base.NoteSourceUnreachable(other, now);
        CHECK_FALSE(base.AddSubscribe(reset));
        CHECK(base.StoredSequence(wrap, other) == std::optional<std::uint16_t>(65535));
        CHECK(base.StoredEpoch(wrap, other) == std::optional<std::uint16_t>(0));
        base.ExpireSubscribeSequences(now + std::chrono::seconds(60));
        CHECK_FALSE(base.StoredSequence(wrap, other).has_value());
        CHECK(base.AddSubscribe(reset));
        CHECK(base.StoredEpoch(wrap, other) == std::optional<std::uint16_t>(1));
        CHECK(base.StoredSequence(wrap, other) == std::optional<std::uint16_t>(0));

        auto old_epoch = Subscribe(0xe02, other, 1);
        old_epoch.details.epoch = 65535;
        CHECK(base.AddSubscribe(old_epoch));
        auto wrapped_epoch = Subscribe(0xe02, other, 0);
        wrapped_epoch.details.epoch = 0;
        CHECK_FALSE(base.AddSubscribe(wrapped_epoch));
        CHECK(base.StoredEpoch(0xe02, other) == std::optional<std::uint16_t>(65535));
    }

    base.SeedSequence(0x111, source, 9);
    CHECK_FALSE(base.GetSubscribe(0x111, source).has_value());
    CHECK(base.AddSubscribe(Subscribe(0x111, source, 9)));
    CHECK_FALSE(base.AddSubscribe(Subscribe(0x111, source, 9)));
    CHECK_FALSE(base.AddSubscribe(Subscribe(0x111, source, 8)));

    const auto rows = base.SequencesFor(source);
    const auto directory =
      std::filesystem::temp_directory_path() / ("moq-peering-seq-test-" + std::to_string(std::rand()));
    std::filesystem::create_directories(directory);
    const auto path = directory / "subscribe-seq";
    CHECK(SaveSubscribeSequenceFile(path, rows));
    const auto loaded = LoadSubscribeSequenceFile(path);
    CHECK_EQ(loaded.size(), rows.size());

    {
        std::ofstream stale(path, std::ios::trunc);
        stale << "1 1\n" << hash << " 4\n";
    }
    const auto continued = LoadSubscribeSequenceFile(path);
    CHECK_EQ(continued.size(), 1);
    CHECK_EQ(continued[0].epoch, 0);
    CHECK_EQ(continued[0].seq, 4);
    {
        std::ofstream current(path, std::ios::trunc);
        current << "2 1\n" << hash << " 7 4\n";
    }
    const auto with_epoch = LoadSubscribeSequenceFile(path);
    CHECK_EQ(with_epoch.size(), 1);
    CHECK_EQ(with_epoch[0].epoch, 7);
    CHECK_EQ(with_epoch[0].seq, 4);
    std::filesystem::remove_all(directory);
}
