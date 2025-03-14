cmake_minimum_required(VERSION 3.15)

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
    target_link_libraries(nosh PRIVATE 
        ws2_32          # For socket functions
        iphlpapi        # For GetAdaptersInfo
        bcrypt         # For BCryptGenRandom
        pdcurses       # For terminal functions
        crypt32        # For crypto functions
        mbedtls
        mbedcrypto 
        mbedx509
        argon2
    )
    
    # Add Windows-specific compile definitions
    target_compile_definitions(nosh PRIVATE 
        _WIN32
        WIN32_LEAN_AND_MEAN
        _GNU_SOURCE
    )
elseif(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    find_library(CORE_FOUNDATION CoreFoundation)
    
    # Find Curses and Readline
    find_package(Curses REQUIRED)
    find_library(READLINE_LIBRARY readline)
    
    # Get Homebrew prefix based on architecture
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
        set(HOMEBREW_PREFIX "/usr/local")
    else()
        set(HOMEBREW_PREFIX "/opt/homebrew")
    endif()

    # Get MbedTLS and Argon2 paths
    execute_process(
        COMMAND ${HOMEBREW_PREFIX}/bin/brew --prefix mbedtls
        OUTPUT_VARIABLE MBEDTLS_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
        COMMAND ${HOMEBREW_PREFIX}/bin/brew --prefix argon2
        OUTPUT_VARIABLE ARGON2_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    
    # Include directories
    include_directories(
        ${CURSES_INCLUDE_DIR}
        ${HOMEBREW_PREFIX}/include
        ${MBEDTLS_PREFIX}/include
        ${ARGON2_PREFIX}/include
    )
    
    # Link directories
    link_directories(
        ${HOMEBREW_PREFIX}/lib
        ${MBEDTLS_PREFIX}/lib
        ${ARGON2_PREFIX}/lib
    )
    
    # Single target_link_libraries call
    target_link_libraries(nosh PRIVATE
        ${SECURITY_FRAMEWORK}
        ${CORE_FOUNDATION}
        "-framework CoreFoundation"
        "-framework Security"
        "-framework CoreServices"
        ${CURSES_LIBRARIES}
        ${READLINE_LIBRARY}
        "${MBEDTLS_PREFIX}/lib/libmbedtls.dylib"
        "${MBEDTLS_PREFIX}/lib/libmbedcrypto.dylib"
        "${MBEDTLS_PREFIX}/lib/libmbedx509.dylib"
        "${ARGON2_PREFIX}/lib/libargon2.dylib"
    )
else()
    # Linux settings
    find_package(OpenSSL REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(MBEDTLS REQUIRED mbedtls)
    pkg_check_modules(ARGON2 REQUIRED libargon2)
    
    target_link_libraries(nosh PRIVATE
        OpenSSL::Crypto
        ${CURSES_LIBRARIES}
        ${READLINE_LIBRARY}
        mbedtls
        mbedcrypto
        mbedx509
        argon2
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
        set(CMAKE_OSX_ARCHITECTURES "x86_64")
        
        execute_process(
            COMMAND /usr/local/bin/brew --prefix mbedtls
            OUTPUT_VARIABLE MBEDTLS_PREFIX
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND /usr/local/bin/brew --prefix argon2
            OUTPUT_VARIABLE ARGON2_PREFIX
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        
        # Add x86_64 specific paths
        include_directories(
            ${HOMEBREW_PREFIX}/include
            ${MBEDTLS_PREFIX}/include
            ${ARGON2_PREFIX}/include
        )
        
        link_directories(
            ${HOMEBREW_PREFIX}/lib
            ${MBEDTLS_PREFIX}/lib
            ${ARGON2_PREFIX}/lib
        )
        
        # Remove duplicate target_link_libraries calls
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
        )
    else()
        set(HOMEBREW_PREFIX "/opt/homebrew")
        set(CMAKE_OSX_ARCHITECTURES "arm64")
        
        execute_process(
            COMMAND /opt/homebrew/bin/brew --prefix mbedtls
            OUTPUT_VARIABLE MBEDTLS_PREFIX
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        execute_process(
            COMMAND /opt/homebrew/bin/brew --prefix argon2
            OUTPUT_VARIABLE ARGON2_PREFIX
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        
        # Add arm64 specific paths
        include_directories(
            ${HOMEBREW_PREFIX}/include
            ${MBEDTLS_PREFIX}/include
            ${ARGON2_PREFIX}/include
        )
        
        link_directories(
            ${HOMEBREW_PREFIX}/lib
            ${MBEDTLS_PREFIX}/lib
            ${ARGON2_PREFIX}/lib
        )
        
        # Remove duplicate target_link_libraries calls
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
        )
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