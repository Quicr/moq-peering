# SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
# SPDX-License-Identifier: BSD-2-Clause

cmake_minimum_required(VERSION 3.16)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

project(moq-peering
        VERSION 0.1.0
        DESCRIPTION "C++ library for Media Over QUIC (MoQ) relay peering"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(MOQ_PEERING_IS_TOP_LEVEL ON)
endif()

# Off when LAPS (or another parent) adds this project. On for a standalone build.
# A parent can still turn either one on.
if(MOQ_PEERING_IS_TOP_LEVEL)
    set(_moq_peering_build_extra_default ON)
else()
    set(_moq_peering_build_extra_default OFF)
endif()
option(MOQ_PEERING_BUILD_TESTS "Build moq-peering tests" ${_moq_peering_build_extra_default})
option(MOQ_PEERING_BUILD_EXAMPLES "Build moq-peering examples" ${_moq_peering_build_extra_default})

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CPM)

# QUIC is picoquic. A parent that already built it, such as LAPS via libquicr, keeps that target.
# Picoquic's TLS is picotls. A standalone build has no picotls on the search path, so picoquic
# fetches it. Homebrew OpenSSL is not on the default search path.
if(NOT TARGET picoquic-core)
    if(APPLE AND NOT OPENSSL_ROOT_DIR AND EXISTS "/opt/homebrew/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3" CACHE PATH "Homebrew OpenSSL" FORCE)
    endif()
    set(BUILD_DEMO OFF CACHE BOOL "" FORCE)
    set(BUILD_HTTP OFF CACHE BOOL "" FORCE)
    set(BUILD_LOGLIB OFF CACHE BOOL "" FORCE)
    set(BUILD_LOGREADER OFF CACHE BOOL "" FORCE)
    set(BUILD_PQBENCH OFF CACHE BOOL "" FORCE)
    set(PICOQUIC_FETCH_PTLS ON CACHE BOOL "Fetch PicoTLS during configuration" FORCE)
    set(picotls_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    CPMAddPackage(
        NAME picoquic
        GITHUB_REPOSITORY private-octopus/picoquic
        GIT_TAG v2026.10.22.70b5fd5
        OPTIONS
            "BUILD_DEMO OFF"
            "BUILD_HTTP OFF"
            "BUILD_LOGLIB OFF"
            "BUILD_LOGREADER OFF"
            "BUILD_PQBENCH OFF"
            "PICOQUIC_FETCH_PTLS ON"
    )
    # picotls.h includes wincompat.h. That header lives in the Visual Studio
    # tree, which the CMake build does not put on the include path. gettimeofday
    # is implemented next to it. The picotls test programs are not part of this
    # library and fail the same way, so leave them out of the default build.
    if(WIN32 AND TARGET picotls-core)
        get_target_property(_picotls_src picotls-core SOURCE_DIR)
        set(_picotls_win "${_picotls_src}/picotlsvs/picotls")
        if(EXISTS "${_picotls_win}/wincompat.h")
            get_property(_picotls_targets DIRECTORY "${_picotls_src}" PROPERTY BUILDSYSTEM_TARGETS)
            foreach(_picotls_tgt IN LISTS _picotls_targets)
                get_target_property(_picotls_type ${_picotls_tgt} TYPE)
                # picotls adds a custom target named check. Include directories apply only to libraries and programs.
                if(_picotls_type STREQUAL "UTILITY" OR _picotls_type STREQUAL "INTERFACE_LIBRARY")
                    continue()
                endif()
                # The compat headers live under the build tree. BUILD_INTERFACE keeps
                # them on the compile line without exporting that path.
                target_include_directories(${_picotls_tgt} PUBLIC "$<BUILD_INTERFACE:${_picotls_win}>")
                if(_picotls_type STREQUAL "EXECUTABLE")
                    set_target_properties(${_picotls_tgt} PROPERTIES EXCLUDE_FROM_ALL TRUE)
                endif()
            endforeach()
            target_sources(picotls-core PRIVATE "${_picotls_win}/wintimeofday.c")
            if(TARGET picotls-minicrypto)
                # picotls already linked this target with the plain signature.
                target_link_libraries(picotls-minicrypto bcrypt)
            endif()
        endif()
    endif()
endif()

if(NOT TARGET spdlog::spdlog)
    if(TARGET fmt::fmt)
        set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "Use the fmt already present in the build" FORCE)
    endif()
    CPMAddPackage("gh:gabime/spdlog@1.17.0")
endif()

add_library(moq-peering STATIC
    src/peer_manager.cc
    src/peering/engine.cc
    src/peering/peer_session.cc
    src/peering/quic_transport.cc
    src/peering/forwarding_base.cc
    src/peering/messages/connect.cc
    src/peering/messages/connect_response.cc
    src/peering/messages/info_base.cc
    src/peering/messages/node_info.cc
    src/peering/messages/subscribe_node_set.cc
    src/peering/messages/data_header.cc
)
add_library(moq::peering ALIAS moq-peering)

target_include_directories(moq-peering
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(moq-peering PUBLIC picoquic-core spdlog::spdlog)

# Static picoquic calls Winsock and IP Helper. Those imports are resolved when
# the final executable is linked, so they have to travel with this library.
if(WIN32)
    target_link_libraries(moq-peering PUBLIC ws2_32 iphlpapi crypt32 bcrypt)
endif()

target_compile_options(moq-peering
    PRIVATE
    $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:-Wall -Wextra -Wpedantic>
)

set_target_properties(moq-peering PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS OFF
)

if(MOQ_PEERING_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(MOQ_PEERING_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
