# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 siakinnik
add_executable(test_core test_core.c)
target_link_libraries(test_core PRIVATE smart_core)
target_include_directories(test_core PRIVATE ../third_party/monocypher)  # RFC vectors call it directly
add_test(NAME core COMMAND test_core)

# A fake device on TCP, for testing hosts (the Python client) without hardware
add_executable(smart_emulator emulator.c)
target_link_libraries(smart_emulator PRIVATE smart_core)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME client
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_client.py $<TARGET_FILE:smart_emulator>)
    # our Noise against an independent implementation (skips without `pip install noiseprotocol`)
    add_test(NAME noise_interop
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_noise_interop.py)
    set_tests_properties(client noise_interop PROPERTIES
        ENVIRONMENT "PYTHONPATH=${PROJECT_SOURCE_DIR}/clients/python")
endif()

# The smallest configuration (what an AVR build would use) must compile too
add_library(smart_core_tiny STATIC ../src/smart_core.c ../src/smart_wire.c)
target_include_directories(smart_core_tiny PUBLIC ../include)
target_compile_definitions(smart_core_tiny PRIVATE
    SMART_ENABLE_DESCRIBE=0 SMART_ENABLE_SECURE=0 SMART_MAX_PROPS=8 SMART_MAX_SESSIONS=1 SMART_MAX_PAYLOAD=48)
target_compile_options(smart_core_tiny PRIVATE -Wall -Wextra -Wpedantic -Werror)
