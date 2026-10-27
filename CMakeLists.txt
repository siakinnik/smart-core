# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 siakinnik
# Builds as an ESP-IDF component (when the submodule sits in components/)
# or as a plain static library + host tests everywhere else.

set(SMART_SOURCES
    src/smart_core.c src/smart_wire.c src/smart_noise.c src/smart_image.c
    third_party/monocypher/monocypher.c third_party/monocypher/monocypher-ed25519.c)

if(ESP_PLATFORM)
    idf_component_register(
        SRCS ${SMART_SOURCES}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "third_party/monocypher")
    return()
endif()

cmake_minimum_required(VERSION 3.16)
project(smart_core C)

add_library(smart_core STATIC ${SMART_SOURCES})
target_include_directories(smart_core PUBLIC include PRIVATE third_party/monocypher)
set_target_properties(smart_core PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # our code is held to -Werror; vendored Monocypher only gets the warnings
    set_source_files_properties(src/smart_core.c src/smart_wire.c src/smart_noise.c src/smart_image.c
        PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Wpedantic;-Werror")
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
    add_subdirectory(tests)
endif()
