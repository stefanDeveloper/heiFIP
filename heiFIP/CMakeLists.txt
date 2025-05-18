cmake_minimum_required(VERSION 3.10)
project(heiFIP)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(/usr/local/include)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_C_FLAGS_DEBUG "-g")

add_compile_options(-Wno-deprecated-declarations)

if (EXISTS "/opt/homebrew")
    set(HOMEBREW_PREFIX "/opt/homebrew")  # Apple Silicon
else()
    set(HOMEBREW_PREFIX "/usr/local")     # Intel
endif()

link_directories(${HOMEBREW_PREFIX}/lib ${OPENSSL_LIBRARIES})
link_directories(/usr/local/lib)
include_directories(${CMAKE_SOURCE_DIR}/assets)
include_directories(${CMAKE_SOURCE_DIR}/plugins)
include_directories(${CMAKE_SOURCE_DIR}/images)
include_directories(${CMAKE_SOURCE_DIR}/layers)
include_directories(
    ${HOMEBREW_PREFIX}/include
    ${HOMEBREW_PREFIX}/include/pcapplusplus
    ${OPENSSL_INCLUDE_DIR}
)

set(OPENSSL_ROOT_DIR "${HOMEBREW_PREFIX}/opt/openssl")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIBRARIES "${OPENSSL_ROOT_DIR}/lib")

add_library(heiFIBPacketImage STATIC assets/heiFIBPacketImage.cpp)
target_include_directories(heiFIBPacketImage PUBLIC ${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)

find_package(OpenCV REQUIRED
    COMPONENTS core imgcodecs   
)

add_executable(main main.cpp)

target_include_directories(main PRIVATE ${OpenCV_INCLUDE_DIRS})
target_link_libraries(main
    Pcap++
    Packet++
    Common++
    pcap
    ${OPENSSL_LIBRARIES}
    ${OpenCV_LIBS}
)