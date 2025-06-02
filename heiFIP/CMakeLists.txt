cmake_minimum_required(VERSION 3.14)
project(heiFIP)

set(CMAKE_CXX_STANDARD 17)

# === 1. Default to Release mode ===
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# === 2. Maximum optimization flags for Release ===
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -funroll-loops -flto=auto -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE   "-O3 -march=native -funroll-loops -flto=auto -DNDEBUG")

# === 3. Manual override support ===

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# --- OpenSSL ---
option(USE_MANUAL_OPENSSL "Use manual OpenSSL paths" OFF)
if(USE_MANUAL_OPENSSL)
    if(NOT DEFINED OPENSSL_INCLUDE_DIR OR NOT DEFINED OPENSSL_CRYPTO_LIBRARY)
        message(FATAL_ERROR "Manual OpenSSL mode requires OPENSSL_INCLUDE_DIR and OPENSSL_CRYPTO_LIBRARY")
    endif()
    set(OpenSSL_INCLUDE_DIRS "${OPENSSL_INCLUDE_DIR}")
    set(OpenSSL_LIBRARIES "${OPENSSL_CRYPTO_LIBRARY}")
    if(DEFINED OPENSSL_SSL_LIBRARY)
        list(APPEND OpenSSL_LIBRARIES "${OPENSSL_SSL_LIBRARY}")
    endif()
else()
    find_package(OpenSSL REQUIRED)
    set(OpenSSL_INCLUDE_DIRS "${OPENSSL_INCLUDE_DIR}")
    set(OpenSSL_LIBRARIES "${OPENSSL_CRYPTO_LIBRARY}")
endif()

# --- OpenCV ---
option(USE_MANUAL_OPENCV "Use manual OpenCV paths" OFF)
if(USE_MANUAL_OPENCV)
    if(NOT DEFINED OpenCV_INCLUDE_DIR OR NOT DEFINED OpenCV_LIBRARIES)
        message(FATAL_ERROR "Manual OpenCV mode requires OpenCV_INCLUDE_DIR and OpenCV_LIBRARIES")
    endif()
    set(OpenCV_INCLUDE_DIRS "${OpenCV_INCLUDE_DIR}")
    set(OpenCV_LIBS "${OpenCV_LIBRARIES}")
else()
    find_package(OpenCV REQUIRED)
    set(OpenCV_INCLUDE_DIRS "${OpenCV_INCLUDE_DIRS}")
    set(OpenCV_LIBS "${OpenCV_LIBRARIES}")
endif()

# --- PcapPlusPlus ---
option(USE_MANUAL_PCAPPLUSPLUS "Use manual PcapPlusPlus paths" OFF)
if(USE_MANUAL_PCAPPLUSPLUS)
    if(NOT DEFINED PcapPlusPlus_INCLUDE_DIRS OR NOT DEFINED PcapPlusPlus_LIBRARIES)
        message(FATAL_ERROR "Manual PcapPlusPlus mode requires PcapPlusPlus_INCLUDE_DIRS and PcapPlusPlus_LIBRARIES")
    endif()
    # Append required external dependencies manually
    list(APPEND PcapPlusPlus_LIBRARIES pcap pthread)
else()
    find_package(PcapPlusPlus REQUIRED)
endif()

# === 4. User project headers ===
include_directories(
    ${CMAKE_SOURCE_DIR}/assets
    ${CMAKE_SOURCE_DIR}/plugins
    ${CMAKE_SOURCE_DIR}/images
    ${CMAKE_SOURCE_DIR}/layers
)

# === 5. Executables ===
add_executable(heiFIP cli.cpp)
add_executable(main   main.cpp)
# main2.cpp removed

# === 6. Apply includes and libraries ===
foreach(_target IN ITEMS heiFIP main)
    target_include_directories(${_target} PUBLIC
        ${PcapPlusPlus_INCLUDE_DIRS}
        ${OpenSSL_INCLUDE_DIRS}
        ${OpenCV_INCLUDE_DIRS}
    )
    target_link_libraries(${_target} PUBLIC
        ${OpenSSL_LIBRARIES}
        ${PcapPlusPlus_LIBRARIES}
        ${OpenCV_LIBS}
    )
endforeach()

# === 7. Optimization and LTO in Release builds ===
foreach(_target IN ITEMS heiFIP main)
    target_compile_options(${_target} PUBLIC
        $<$<CONFIG:Release>:-O3 -march=native -funroll-loops -flto=auto -DNDEBUG>
    )
    target_link_options(${_target} PUBLIC
        $<$<CONFIG:Release>:-flto=auto>
    )
endforeach()