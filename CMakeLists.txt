cmake_minimum_required(VERSION 3.10)

# Version components
set(NOSH_VERSION_MAJOR 0)
set(NOSH_VERSION_MINOR 1)
set(NOSH_VERSION_PATCH 0)

# Create base version string
set(NOSH_BASE_VERSION "${NOSH_VERSION_MAJOR}.${NOSH_VERSION_MINOR}.${NOSH_VERSION_PATCH}")

# Get git commit hash for version string
execute_process(
    COMMAND git rev-parse --short HEAD
    OUTPUT_VARIABLE GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

if(NOT GIT_COMMIT)
    set(GIT_COMMIT "unknown")
endif()

# Create version string matching GitHub Actions format
set(NOSH_VERSION "${NOSH_BASE_VERSION}-${GIT_COMMIT}")

# Start project with base version
project(nosh VERSION ${NOSH_BASE_VERSION})

# Configure version header
configure_file(
    "${PROJECT_SOURCE_DIR}/include/version.h.in"
    "${PROJECT_BINARY_DIR}/include/version.h"
    @ONLY
)

# Include directories for the build
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/include
)

set(CMAKE_C_STANDARD 99)

# Include directories
include_directories(include)

# Source files
file(GLOB SOURCES "src/*.c")

# Add executable
add_executable(nosh ${SOURCES})

# Platform-specific settings
if(WIN32)
    target_link_libraries(nosh PRIVATE crypt32)
    
    # Use vcpkg's find_package for mbedtls
    find_package(mbedtls CONFIG REQUIRED)
    
    # Direct path to Argon2 for Windows
    set(ARGON2_ROOT "${CMAKE_PREFIX_PATH}/installed/x64-windows")
    include_directories("${ARGON2_ROOT}/include")
    target_link_libraries(nosh PRIVATE 
        MbedTLS::mbedtls
        MbedTLS::mbedcrypto 
        MbedTLS::mbedx509
        "${ARGON2_ROOT}/lib/argon2.lib")
    
    # Windows doesn't use readline/curses
    add_definitions(-DWINDOWS_BUILD)
    
elseif(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    find_library(CORE_FOUNDATION CoreFoundation)
    
    # Get MbedTLS and Argon2 paths from Homebrew
    execute_process(
        COMMAND brew --prefix mbedtls
        OUTPUT_VARIABLE MBEDTLS_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    execute_process(
        COMMAND brew --prefix argon2
        OUTPUT_VARIABLE ARGON2_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    # Add include directories
    include_directories(
        "${MBEDTLS_PREFIX}/include"
        "${ARGON2_PREFIX}/include"
    )
    
    # Find Curses and Readline for Unix-like systems
    find_package(Curses REQUIRED)
    find_library(READLINE_LIBRARY readline)
    include_directories(${CURSES_INCLUDE_DIR})
    
    target_link_libraries(nosh PRIVATE
        ${SECURITY_FRAMEWORK}
        ${CORE_FOUNDATION}
        "-framework CoreFoundation"
        "-framework Security"
        "-framework CoreServices"
        "${MBEDTLS_PREFIX}/lib/libmbedtls.dylib"
        "${MBEDTLS_PREFIX}/lib/libmbedcrypto.dylib"
        "${MBEDTLS_PREFIX}/lib/libmbedx509.dylib"
        "${ARGON2_PREFIX}/lib/libargon2.dylib"
        ${CURSES_LIBRARIES}
        ${READLINE_LIBRARY}
        c
    )
    
    # Set deployment target for macOS
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum OS X deployment version")
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(nosh PRIVATE OpenSSL::Crypto)

    # Linux dependencies
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(MBEDTLS REQUIRED mbedtls)
    include_directories(${MBEDTLS_INCLUDE_DIRS})
    link_directories(${MBEDTLS_LIBRARY_DIRS})
    
    # Find Curses and Readline for Unix-like systems
    find_package(Curses REQUIRED)
    find_library(READLINE_LIBRARY readline)
    include_directories(${CURSES_INCLUDE_DIR})
    
    target_link_libraries(nosh PRIVATE
        mbedtls
        mbedcrypto
        mbedx509
        argon2
        ${CURSES_LIBRARIES}
        ${READLINE_LIBRARY}
    )
endif()

# Handle Argon2 library path for macOS
if(APPLE)
    execute_process(
        COMMAND brew --prefix argon2
        OUTPUT_VARIABLE ARGON2_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    target_link_libraries(nosh PRIVATE "${ARGON2_PREFIX}/lib/libargon2.dylib")
endif()

# Add architecture-specific library paths
if(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        set(HOMEBREW_PREFIX "/usr/local")
    else()
        set(HOMEBREW_PREFIX "/opt/homebrew")
    endif()
    
    include_directories(
        ${HOMEBREW_PREFIX}/include
    )
    
    link_directories(
        ${HOMEBREW_PREFIX}/lib
    )
endif()

# Ensure proper linking
target_link_libraries(nosh
    PRIVATE
    readline
    mbedtls
    mbedcrypto 
    mbedx509
    argon2
)

# Install target
if(UNIX)
    install(TARGETS nosh DESTINATION /usr/local/bin)
    
    # Custom install command to set nosh as the default shell
    install(CODE "
    execute_process(COMMAND echo \"/usr/local/bin/nosh\" | sudo tee -a /etc/shells)
    execute_process(COMMAND sudo chsh -s /usr/local/bin/nosh \$USER)
    file(WRITE \$ENV{HOME}/.nosh_backup \$ENV{SHELL})
    ")
    
    # Custom uninstall command
    add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake)
    
    # Create cmake_uninstall.cmake script
    file(WRITE ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake "
    if(EXISTS \"/usr/local/bin/nosh\")
    ")
endif()