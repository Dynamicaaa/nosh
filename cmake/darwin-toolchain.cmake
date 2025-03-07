set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify the cross compilers
set(CMAKE_C_COMPILER ${OSXCROSS_ROOT}/target/bin/o64-clang)
set(CMAKE_CXX_COMPILER ${OSXCROSS_ROOT}/target/bin/o64-clang++)

# Set the OSX sysroot
set(CMAKE_OSX_SYSROOT ${OSXCROSS_ROOT}/target/SDK/MacOSX11.3.sdk)

# Set deployment target
set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum OS X deployment version")

# Where to look for libraries and headers
set(CMAKE_FIND_ROOT_PATH ${OSXCROSS_ROOT}/target/SDK/MacOSX11.3.sdk)

# Adjust the default behavior of find_XXX() commands
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)