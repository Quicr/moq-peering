# SPDX-FileCopyrightText: Copyright (c) 2024 Cisco Systems
# SPDX-License-Identifier: BSD-2-Clause

if(APPLE AND NOT OPENSSL_ROOT_DIR AND EXISTS "/opt/homebrew/opt/openssl@3")
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3" CACHE PATH "Homebrew OpenSSL" FORCE)
endif()
find_package(OpenSSL REQUIRED)

set(MOQ_PEERING_EXAMPLES moq_peering_relay moq_peering_producer moq_peering_subscriber)

add_executable(moq_peering_relay relay.cc example_util.cc)
add_executable(moq_peering_producer producer.cc example_util.cc)
add_executable(moq_peering_subscriber subscriber.cc example_util.cc)

foreach(example IN LISTS MOQ_PEERING_EXAMPLES)
    target_link_libraries(${example} PRIVATE moq-peering OpenSSL::Crypto)
    target_compile_features(${example} PRIVATE cxx_std_20)
    target_compile_options(${example}
        PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:-Wall -Wextra -Wpedantic>
    )
endforeach()
