# Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

add_executable(streamhashd)

target_sources(streamhashd
    PRIVATE
        streamhashd.c
        streamhash_server.c
        streamhash_server.h
        streamhash_hash.c
        streamhash_hash.h
        streamhash_session.c
        streamhash_session.h)

target_include_directories(streamhashd
    PRIVATE
        ${CMAKE_BINARY_DIR}          # For clamav-config.h
        ${CMAKE_SOURCE_DIR}/common   # Common utilities
        ${CMAKE_SOURCE_DIR}/clamd    # For server architecture reference
)

set_target_properties(streamhashd PROPERTIES COMPILE_FLAGS "${WARNCFLAGS}")

target_link_libraries(streamhashd
    PRIVATE
        ClamAV::libclamav
        ClamAV::common
        ${CMAKE_THREAD_LIBS_INIT}
        ${JSONC_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        fuzzy
)

if(WIN32)
    install(TARGETS streamhashd DESTINATION . COMPONENT programs)
    install(FILES streamhashd.conf.sample DESTINATION . COMPONENT programs)
else()
    install(TARGETS streamhashd DESTINATION ${CMAKE_INSTALL_SBINDIR} COMPONENT programs)
    install(FILES streamhashd.conf.sample DESTINATION ${CMAKE_INSTALL_SYSCONFDIR} COMPONENT programs)
endif()