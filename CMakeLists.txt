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
    set(MBEDTLS_ROOT "C:/Program Files/mbedtls")
    set(ARGON2_ROOT "C:/ProgramData/chocolatey/lib/libargon2")
    
    include_directories(
        "${MBEDTLS_ROOT}/include"
        "${ARGON2_ROOT}/include"
    )
    
    link_directories(
        "${MBEDTLS_ROOT}/lib"
        "${ARGON2_ROOT}/lib"
    )
elseif(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    find_library(CORE_FOUNDATION CoreFoundation)
    
    target_link_libraries(nosh PRIVATE
        ${SECURITY_FRAMEWORK}
        ${CORE_FOUNDATION}
        "-framework CoreFoundation"
        "-framework Security"
        "-framework CoreServices"
        c
    )
    
    # Set deployment target for macOS
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum OS X deployment version")
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(nosh PRIVATE OpenSSL::Crypto)
endif()

# Find readline dependency
find_package(Curses REQUIRED)
find_library(READLINE_LIBRARY readline)
target_link_libraries(nosh PRIVATE ${CURSES_LIBRARIES} ${READLINE_LIBRARY})

# Find MbedTLS dependency
find_package(MbedTLS REQUIRED)
target_link_libraries(nosh PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)

# Find Argon2 dependency
find_package(PkgConfig REQUIRED)
pkg_check_modules(ARGON2 REQUIRED libargon2)
include_directories(${ARGON2_INCLUDE_DIRS})
link_directories(${ARGON2_LIBRARY_DIRS})

# Explicitly set the Argon2 library path for macOS
if(APPLE)
    target_link_libraries(nosh PRIVATE /usr/local/Cellar/argon2/20190702_1/lib/libargon2.dylib)
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