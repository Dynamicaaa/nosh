cmake_minimum_required(VERSION 3.10)
project(nosh)

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
    
    target_link_libraries(nosh PRIVATE
        mbedtls
        mbedcrypto
        mbedx509
        argon2
    )
endif()

# Find readline dependency
find_package(Curses REQUIRED)
find_library(READLINE_LIBRARY readline)
target_link_libraries(nosh PRIVATE ${CURSES_LIBRARIES} ${READLINE_LIBRARY})

# Find Argon2 dependency
find_package(PkgConfig REQUIRED)
pkg_check_modules(ARGON2 REQUIRED libargon2)
include_directories(${ARGON2_INCLUDE_DIRS})
link_directories(${ARGON2_LIBRARY_DIRS})

# Handle Argon2 library path for macOS
if(APPLE)
    execute_process(
        COMMAND brew --prefix argon2
        OUTPUT_VARIABLE ARGON2_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    target_link_libraries(nosh PRIVATE "${ARGON2_PREFIX}/lib/libargon2.dylib")
else()
    target_link_libraries(nosh PRIVATE ${ARGON2_LIBRARIES})
endif()

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