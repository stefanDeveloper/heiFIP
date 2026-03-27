cmake_minimum_required(VERSION 3.14)
project(heiFIP)

set(CMAKE_CXX_STANDARD 20)

# === 1. Default to Release mode ===
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# === 2. Maximum optimization flags for Release ===
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -funroll-loops -flto=auto -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE   "-O3 -march=native -funroll-loops -flto=auto -DNDEBUG")

# === 3. Find dependencies ===

find_package(OpenSSL REQUIRED)
find_package(OpenCV REQUIRED)
find_package(PcapPlusPlus CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

# === 4. User project headers ===
include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/assets
    ${CMAKE_SOURCE_DIR}/plugins
    ${CMAKE_SOURCE_DIR}/images
    ${CMAKE_SOURCE_DIR}/layers
)

# === 5. Enable Testing ===
enable_testing()

# === 6. Common Libraries ===
set(HEIFIP_LIBS
    OpenSSL::Crypto
    OpenSSL::SSL
    PcapPlusPlus::Common++
    PcapPlusPlus::Packet++
    PcapPlusPlus::Pcap++
    ${OpenCV_LIBS}
)

# === 7. Executables ===
add_executable(heiFIP cli.cpp)
add_executable(main   main.cpp)

# === 8. Tests ===
add_executable(heiFIP_tests 
    tests/test_packet_image.cpp
    tests/test_flow_image.cpp
    tests/test_tiled_images.cpp
    tests/test_markov.cpp
    tests/test_tile_utils.cpp
    tests/test_extractor.cpp
    tests/test_layers.cpp
    tests/test_cli.cpp
)

# === 9. Apply libraries ===
foreach(_target IN ITEMS heiFIP main heiFIP_tests)
    target_link_libraries(${_target} PUBLIC ${HEIFIP_LIBS})
endforeach()

target_link_libraries(heiFIP_tests PUBLIC GTest::gtest_main)

# === 10. Optimization and LTO in Release builds ===
foreach(_target IN ITEMS heiFIP main heiFIP_tests)
    target_compile_options(${_target} PUBLIC
        $<$<CONFIG:Release>:-O3 -march=native -funroll-loops -flto=auto -DNDEBUG>
    )
    target_link_options(${_target} PUBLIC
        $<$<CONFIG:Release>:-flto=auto>
    )
endforeach()

include(GoogleTest)
gtest_discover_tests(heiFIP_tests)