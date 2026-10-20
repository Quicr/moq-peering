# SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
# SPDX-License-Identifier: BSD-2-Clause

if(NOT TARGET doctest::doctest)
    CPMAddPackage("gh:doctest/doctest@2.4.11")
endif()

add_executable(moq_peering_test
    main.cc
    peering_node.cc
    peering_connect.cc
    peering_subscribe.cc
    peering_announce.cc
    peering_sns.cc
    peering_data_header.cc
    peering_info_base.cc
)
target_include_directories(moq_peering_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(moq_peering_test PRIVATE moq-peering doctest::doctest)
set_target_properties(moq_peering_test PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS OFF
)

enable_testing()
add_test(NAME moq_peering_test COMMAND moq_peering_test)
