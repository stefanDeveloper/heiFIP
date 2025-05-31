# --- cmake/Modules/FindOpenSSL.cmake ---

# 1) Locate the directory that contains openssl/sha.h
find_path(OPENSSL_INCLUDE_DIR
  NAMES openssl/sha.h
  PATHS
    $ENV{OPENSSL_ROOT_DIR}/include                  # if user set OPENSSL_ROOT_DIR
    /opt/homebrew/Cellar/openssl@3/*/include        # glob into all versions
    /opt/homebrew/include                            # Homebrew “flat” symlink
    /usr/local/include
    /usr/include
)

# 2) Locate the libraries (unchanged)
find_library(OPENSSL_CRYPTO_LIBRARY
  NAMES crypto
  PATHS
    $ENV{OPENSSL_ROOT_DIR}/lib
    /opt/homebrew/Cellar/openssl@3/*/lib
    /opt/homebrew/lib
    /usr/local/lib
    /usr/lib
  NO_DEFAULT_PATH
)
find_library(OPENSSL_SSL_LIBRARY
  NAMES ssl
  PATHS
    $ENV{OPENSSL_ROOT_DIR}/lib
    /opt/homebrew/Cellar/openssl@3/*/lib
    /opt/homebrew/lib
    /usr/local/lib
    /usr/lib
  NO_DEFAULT_PATH
)

# 3) Standard boilerplate
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenSSL
  REQUIRED_VARS OPENSSL_INCLUDE_DIR
                OPENSSL_CRYPTO_LIBRARY
                OPENSSL_SSL_LIBRARY
)

if(OpenSSL_FOUND)
  set(OpenSSL_INCLUDE_DIRS   "${OPENSSL_INCLUDE_DIR}")
  set(OpenSSL_LIBRARIES
      "${OPENSSL_SSL_LIBRARY}"
      "${OPENSSL_CRYPTO_LIBRARY}"
  )
endif()