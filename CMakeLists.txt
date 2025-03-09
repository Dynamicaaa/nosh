cmake_minimum_required(VERSION 3.15)

# Version components
set(NOSH_VERSION_MAJOR 0)
set(NOSH_VERSION_MINOR 1)
set(NOSH_VERSION_PATCH 1)

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
    # Windows-specific DLL handling
    # Define base DLL names using wildcard patterns
    set(REQUIRED_DLL_PATTERNS
        "libmbedtls*.dll"
        "libmbedcrypto*.dll"
        "libmbedx509*.dll"
        "libargon2*.dll"
        "pdcurses.dll"
        "libreadline*.dll"
        "libgcc_s_seh*.dll"
        "libwinpthread*.dll"
        "libtermcap*.dll"
    )

    # Multiple search paths for DLLs
    set(DLL_SEARCH_PATHS
        "${CMAKE_SOURCE_DIR}/dll"
        "C:/msys64/mingw64/bin"
        "C:/msys64/mingw64/lib"
        "$ENV{PATH}"
    )

    # Remove old bin directory and create a clean one
    add_custom_command(TARGET nosh PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E remove_directory "$<TARGET_FILE_DIR:nosh>/bin"
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:nosh>/bin"
        COMMENT "Creating clean bin directory"
    )

    # Copy nosh.exe to bin directory
    add_custom_command(TARGET nosh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different 
            "$<TARGET_FILE:nosh>"
            "$<TARGET_FILE_DIR:nosh>/bin/nosh.exe"
        COMMENT "Copying nosh.exe to bin directory"
    )

    # Find and copy DLLs using wildcard patterns
    foreach(pattern ${REQUIRED_DLL_PATTERNS})
        unset(DLL_MATCHES CACHE)
        file(GLOB DLL_MATCHES
            LIST_DIRECTORIES false
            RELATIVE "${CMAKE_CURRENT_BINARY_DIR}"
            ${DLL_SEARCH_PATHS}/${pattern}
        )
        
        if(DLL_MATCHES)
            # Take the first match for each pattern
            list(GET DLL_MATCHES 0 DLL_PATH)
            add_custom_command(TARGET nosh POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different 
                    "${DLL_PATH}" 
                    "$<TARGET_FILE_DIR:nosh>/bin/"
                COMMENT "Copying ${DLL_PATH} to bin directory"
            )
        else()
            message(WARNING "Could not find any DLL matching pattern: ${pattern}")
        endif()
    endforeach()

    # Windows-specific compiler definitions and libraries
    target_compile_definitions(nosh PRIVATE 
        _WIN32
        WIN32_LEAN_AND_MEAN
        _GNU_SOURCE
        NO_PWD_H
    )

    # Add Windows-specific libraries
    target_link_libraries(nosh PRIVATE
        ws2_32    # Windows Sockets 2
        iphlpapi  # IP Helper API
    )

elseif(APPLE)
    # macOS-specific settings
    find_library(SECURITY_FRAMEWORK Security)
    find_library(CORE_FOUNDATION CoreFoundation)
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
    
    target_compile_definitions(nosh PRIVATE 
        _POSIX_C_SOURCE=200809L
        _DEFAULT_SOURCE
        _GNU_SOURCE
    )

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

# After the platform-specific settings section:

if(WIN32)
    # Windows-specific DLL handling (additional set)
    # Remove the old bin directory and create a clean one.
    add_custom_command(TARGET nosh PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E remove_directory "$<TARGET_FILE_DIR:nosh>/bin"
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:nosh>/bin"
        COMMENT "Creating clean bin directory"
    )

    # Copy nosh.exe to bin directory after build
    add_custom_command(TARGET nosh POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different 
            "$<TARGET_FILE:nosh>"
            "$<TARGET_FILE_DIR:nosh>/bin/nosh.exe"
        COMMENT "Copying nosh.exe to bin directory"
    )

    # Define required DLLs for additional dependencies
    set(REQUIRED_DLLS
        "libmbedcrypto-16.dll"
        "libargon2.dll"
        "libreadline8.dll"
        "libgcc_s_seh-1.dll"
        "libwinpthread-1.dll"
        "libtermcap-0.dll"
    )

    # Multiple search paths for DLLs
    set(DLL_SEARCH_PATHS
        "${CMAKE_SOURCE_DIR}/dll"
        "C:/msys64/mingw64/bin"
        "C:/msys64/mingw64/lib"
        "$ENV{PATH}"
    )

    # Copy each required DLL to bin directory
    foreach(dll ${REQUIRED_DLLS})
        unset(DLL_PATH CACHE)
        find_file(DLL_PATH ${dll}
            PATHS ${DLL_SEARCH_PATHS}
            NO_DEFAULT_PATH
        )
        
        if(DLL_PATH)
            add_custom_command(TARGET nosh POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different 
                    "${DLL_PATH}" 
                    "$<TARGET_FILE_DIR:nosh>/bin/${dll}"
                COMMENT "Copying ${dll} to bin directory"
            )
        else()
            message(WARNING "Could not find ${dll} in search paths")
        endif()
        unset(DLL_PATH CACHE)
    endforeach()
endif()

# After the platform-specific settings

if(WIN32)
    target_compile_definitions(nosh PRIVATE 
        _WIN32
        WIN32_LEAN_AND_MEAN
        _GNU_SOURCE
        NO_PWD_H  # Add this to indicate pwd.h is not available
    )
else()
    target_compile_definitions(nosh PRIVATE 
        _POSIX_C_SOURCE=200809L
        _DEFAULT_SOURCE
        _GNU_SOURCE
    )

    # Check for required headers on Unix-like systems
    include(CheckIncludeFile)
    check_include_file(pwd.h HAVE_PWD_H)
    check_include_file(unistd.h HAVE_UNISTD_H)
    
    if(NOT HAVE_PWD_H)
        message(FATAL_ERROR "pwd.h not found - required for Unix-like systems")
    endif()
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

# Add architecture-specific library paths for macOS
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
        execute_process(COMMAND sudo rm /usr/local/bin/nosh)
        if(EXISTS \$ENV{HOME}/.nosh_backup)
            file(READ \$ENV{HOME}/.nosh_backup BACKUP_SHELL)
            execute_process(COMMAND sudo chsh -s \${BACKUP_SHELL} \$USER)
            file(REMOVE \$ENV{HOME}/.nosh_backup)
        endif()
    endif()
    ")
endif()