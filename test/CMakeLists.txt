# SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
# SPDX-License-Identifier: BSD-2-Clause

if(NOT TARGET doctest::doctest)
    CPMAddPackage("gh:doctest/doctest@2.4.11")
endif()

# CPM puts the CMake helper next to the fetched sources. A parent build that
# already provided doctest exposes the same tree through the include directory.
if(NOT DEFINED doctest_SOURCE_DIR)
    get_target_property(_doctest_include doctest::doctest INTERFACE_INCLUDE_DIRECTORIES)
    list(GET _doctest_include 0 _doctest_include)
    get_filename_component(doctest_SOURCE_DIR "${_doctest_include}" DIRECTORY)
endif()
include("${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake")

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

doctest_discover_tests(moq_peering_test)
