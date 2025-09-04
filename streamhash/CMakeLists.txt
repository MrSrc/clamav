# Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

add_executable(streamhash)

target_sources(streamhash
    PRIVATE
        streamhash_simple.c
        streamhash_client.c
        streamhash_client.h
        streamhash_protocol.c
        streamhash_protocol.h)

target_include_directories(streamhash
    PRIVATE
        ${CMAKE_BINARY_DIR}            # For clamav-config.h
        ${CMAKE_SOURCE_DIR}/common     # Common utilities
        ${CMAKE_SOURCE_DIR}/clamdscan  # For client architecture reference
)

set_target_properties(streamhash PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")

target_link_libraries(streamhash
    PRIVATE
        ClamAV::libclamav
        ClamAV::common
        ${JSONC_LIBRARIES}
)

if(WIN32)
    install(TARGETS streamhash DESTINATION . COMPONENT programs)
else()
    install(TARGETS streamhash DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT programs)
endif()