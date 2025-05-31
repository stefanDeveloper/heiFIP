cmake_minimum_required(VERSION 3.14)
project(heiFIP)

set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build (Debug or Release)" FORCE
  )
endif()

# Your own include dirs
include_directories(
  ${CMAKE_SOURCE_DIR}/assets
  ${CMAKE_SOURCE_DIR}/plugins
  ${CMAKE_SOURCE_DIR}/images
  ${CMAKE_SOURCE_DIR}/layers
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
message(STATUS "CMAKE_MODULE_PATH = ${CMAKE_MODULE_PATH}")

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL include dirs: ${OpenSSL_INCLUDE_DIRS}")
message(STATUS "OpenSSL libraries:   ${OpenSSL_LIBRARIES}")

find_package( OpenCV REQUIRED )
message(STATUS "Opencv include dirs: ${OpenCV_INCLUDE_DIRS}")
message(STATUS "Opencv libraries:   ${OpenCV_LIBRARIES}")

find_package(PcapPlusPlus REQUIRED)
message(STATUS "PcapPlusPlus include dirs: ${PcapPlusPlus_INCLUDE_DIRS}")
message(STATUS "PcapPlusPlus libraries:   ${PcapPlusPlus_LIBRARIES}")

# === Your executables ===
add_executable(heiFIP cli.cpp)
add_executable(main  main.cpp)

# === Link against PcapPlusPlus, OpenSSL, OpenCV, and libpcap ===
target_include_directories(heiFIP PUBLIC
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${OpenSSL_INCLUDE_DIRS}
    ${OpenCV_INCLUDE_DIRS}
)

target_link_libraries(heiFIP PUBLIC
  ${OPENSSL_CRYPTO_LIBRARY}
  ${OPENSSL_LIBRARIES}
  ${PcapPlusPlus_LIBRARIES}
  ${OpenCV_LIBS}
)

target_include_directories(main PUBLIC
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${OpenSSL_INCLUDE_DIRS}
    ${OpenCV_INCLUDE_DIRS}
)

target_link_libraries(main PUBLIC
  ${OPENSSL_CRYPTO_LIBRARY}
  ${OPENSSL_LIBRARIES}
  ${PcapPlusPlus_LIBRARIES}
  ${OpenCV_LIBS}
)