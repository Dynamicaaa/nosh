cmake_minimum_required(VERSION 3.10)
project(nosh)

set(CMAKE_C_STANDARD 99)

# Include directories
include_directories(include)

# Source files
file(GLOB SOURCES "src/*.c")

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Find readline
pkg_check_modules(READLINE REQUIRED readline)

# Add executable
add_executable(nosh ${SOURCES})

# Link libraries
target_link_libraries(nosh ${SODIUM_LIBRARIES} ${READLINE_LIBRARIES})
target_include_directories(nosh PRIVATE ${SODIUM_INCLUDE_DIRS} ${READLINE_INCLUDE_DIRS})

# Install target
install(TARGETS nosh DESTINATION /usr/local/bin)

# Custom install command to set nosh as the default shell
install(CODE "
execute_process(COMMAND echo \"/usr/local/bin/nosh\" | sudo tee -a /etc/shells)
execute_process(COMMAND sudo chsh -s /usr/local/bin/nosh \$USER)
")

# Custom uninstall command to remove nosh as the default shell
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake)

# Create cmake_uninstall.cmake script
file(WRITE ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake "
if(EXISTS \"/usr/local/bin/nosh\")
    execute_process(COMMAND sudo sed -i.bak \"/\\/usr\\/local\\/bin\\/nosh/d\" /etc/shells)
    execute_process(COMMAND sudo rm -f /usr/local/bin/nosh)
    if(EXISTS \"\$ENV{HOME}/.nosh_backup\")
        file(READ \$ENV{HOME}/.nosh_backup ORIGINAL_SHELL)
        execute_process(COMMAND sudo chsh -s \${ORIGINAL_SHELL} \$USER)
        file(REMOVE \$ENV{HOME}/.nosh_backup)
    endif()
endif()
")