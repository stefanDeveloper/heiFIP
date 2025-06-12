# cmake/Modules/FindPcapPlusPlus.cmake

# 1) Locate the headers
# --- find the raw include dir (may end up being /opt/homebrew/include) ---
find_path(PPCPP_INCLUDE_DIR
  NAMES SystemUtils.h
  PATHS
    $ENV{PCAPPLUSPLUS_ROOT}/include/pcapplusplus     # direct Cellar path
    /opt/homebrew/include/pcapplusplus              # Homebrew symlink
  HINTS
    $ENV{PCAPPLUSPLUS_ROOT}
    /usr/local
    /usr
)

# --- if CMake only found the parent 'include' directory, but
#     the real headers are under include/pcapplusplus, fix it up ---
if(PPCPP_INCLUDE_DIR)
  # e.g. PPCPP_INCLUDE_DIR = /opt/homebrew/include
  if(NOT EXISTS "${PPCPP_INCLUDE_DIR}/SystemUtils.h"
     AND EXISTS "${PPCPP_INCLUDE_DIR}/pcapplusplus/SystemUtils.h")
    message(STATUS "  >> Adjusting Ppcpp include dir to subfolder ‘pcapplusplus/’")
    set(PPCPP_INCLUDE_DIR "${PPCPP_INCLUDE_DIR}/pcapplusplus")
  endif()
endif()

# 2) Locate the libraries
find_library(PPCPP_COMMONPP_LIB
  NAMES Common++
  HINTS
    ENV PCAPPLUSPLUS_ROOT
    /usr/local/lib
    /opt/homebrew/lib
    /usr/lib
)
find_library(PPCPP_PACKETPP_LIB
  NAMES Packet++
  HINTS
    ENV PCAPPLUSPLUS_ROOT
    /usr/local/lib
    /opt/homebrew/lib
    /usr/lib
)
find_library(PPCPP_PCAPPP_LIB
  NAMES Pcap++
  HINTS
    ENV PCAPPLUSPLUS_ROOT
    /usr/local/lib
    /opt/homebrew/lib
    /usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PcapPlusPlus
  REQUIRED_VARS PPCPP_INCLUDE_DIR
                PPCPP_COMMONPP_LIB
                PPCPP_PACKETPP_LIB
                PPCPP_PCAPPP_LIB
)

if(PcapPlusPlus_FOUND)
  set(PcapPlusPlus_INCLUDE_DIRS "${PPCPP_INCLUDE_DIR}")
  set(PcapPlusPlus_LIBRARIES
      ${PPCPP_COMMONPP_LIB}
      ${PPCPP_PACKETPP_LIB}
      ${PPCPP_PCAPPP_LIB}
      pcap
      pthread
  )
endif()