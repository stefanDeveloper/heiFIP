cmake_minimum_required(VERSION 3.14)
project(heiFIP)

set(CMAKE_CXX_STANDARD 20)

# === 1. Default to Release mode ===
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# === 2. Maximum optimization flags for Release ===
if(MSVC)
  set(CMAKE_CXX_FLAGS_RELEASE "/O2 /GL /DNDEBUG")
  set(CMAKE_C_FLAGS_RELEASE   "/O2 /GL /DNDEBUG")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -funroll-loops -flto=auto -DNDEBUG")
  set(CMAKE_C_FLAGS_RELEASE   "-O3 -funroll-loops -flto=auto -DNDEBUG")
endif()

# === 3. Find dependencies ===

find_package(OpenSSL REQUIRED)
find_package(OpenCV REQUIRED)
find_package(PcapPlusPlus CONFIG REQUIRED)
if(WIN32)
  find_package(getopt-win32 CONFIG REQUIRED)
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

# === 6. Apply libraries ===
foreach(_target IN ITEMS heiFIP main)
    target_link_libraries(${_target} PUBLIC
        OpenSSL::Crypto
        OpenSSL::SSL
        PcapPlusPlus::Common++
        PcapPlusPlus::Packet++
        PcapPlusPlus::Pcap++
        ${OpenCV_LIBS}
    )
    if(WIN32)
        target_link_libraries(${_target} PUBLIC getopt-win32::getopt)
    endif()
endforeach()

# === 8. Install rules ===
install(TARGETS heiFIP RUNTIME DESTINATION bin)
# Optionally install assets if needed
# install(DIRECTORY assets DESTINATION share/heiFIP)

# === 7. Optimization and LTO in Release builds ===
foreach(_target IN ITEMS heiFIP main)
    if(MSVC)
        target_compile_options(${_target} PUBLIC
            $<$<CONFIG:Release>:/O2 /GL /DNDEBUG>
        )
        target_link_options(${_target} PUBLIC
            $<$<CONFIG:Release>:/LTCG>
        )
    else()
        target_compile_options(${_target} PUBLIC
            $<$<CONFIG:Release>:-O3 -funroll-loops -flto=auto -DNDEBUG>
        )
        target_link_options(${_target} PUBLIC
            $<$<CONFIG:Release>:-flto=auto>
        )
    endif()
endforeach()