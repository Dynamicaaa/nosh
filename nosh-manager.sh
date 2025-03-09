#!/bin/bash

NO_INTERACTION=0
INSTALL_FLAG=0
COMPILE_FLAG=0
UNINSTALL_FLAG=0
REQUIREMENTS_FLAG=0
DEFAULT_SHELL_FLAG=0
RESTORE_SHELL_FLAG=0
NETWORK_FLAG=0
YES_FLAG=0
HELP_FLAG=0

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print with colors
print_status() {
    local color=$1
    local message=$2
    case $color in
        "green") echo -e "\033[32m${message}\033[0m" ;;
        "red") echo -e "\033[31m${message}\033[0m" ;;
        "yellow") echo -e "\033[33m${message}\033[0m" ;;
        *) echo "${message}" ;;
    esac
}

# Update existing show_menu function to be for management
show_menu() {
    clear
    print_status "green" "NOSH Management Menu"
    echo "1. Reinstall nosh"
    echo "2. Uninstall nosh"
    echo "3. Recompile only"
    echo "4. Change shell settings"
    echo "5. Show build requirements"
    if [[ "$OSTYPE" == "darwin"* ]] && ! command_exists brew; then
        echo "6. Install Homebrew"
        echo "7. Exit"
        echo
        read -p "Please select an option [1-7]: " choice
        
        case $choice in
            1) handle_reinstall ;;
            2) handle_uninstall ;;
            3) handle_recompile ;;
            4) handle_shell_settings ;;
            5) show_requirements ;;
            6) install_homebrew ;;
            7) exit 0 ;;
            *) print_status "red" "Invalid option" ;;
        esac
    else
        echo "6. Exit"
        echo
        read -p "Please select an option [1-6]: " choice
        
        case $choice in
            1) handle_reinstall ;;
            2) handle_uninstall ;;
            3) handle_recompile ;;
            4) handle_shell_settings ;;
            5) show_requirements ;;
            6) exit 0 ;;
            *) print_status "red" "Invalid option" ;;
        esac
    fi
}

# Function to handle reinstallation
handle_reinstall() {
    print_status "yellow" "Uninstalling existing installation..."
    if [[ -f build/cmake_uninstall.cmake ]]; then
        cd build && make uninstall && cd ..
    fi
    rm -rf build
    build_and_install
}

# Update handle_uninstall function
handle_uninstall() {
    print_status "yellow" "Uninstalling nosh..."
    
    # First restore original shell if needed
    if [[ -f ~/.nosh_backup ]]; then
        ORIG_SHELL=$(cat ~/.nosh_backup)
        if [ -x "$ORIG_SHELL" ]; then
            # Change shell before removing backup file
            sudo chsh -s "$ORIG_SHELL" "$USER"
            if [ $? -eq 0 ]; then
                print_status "green" "Restored original shell: $ORIG_SHELL"
                # Remove backup file with proper permissions handling
                rm -f ~/.nosh_backup 2>/dev/null || sudo rm -f ~/.nosh_backup
            else
                print_status "red" "Failed to restore original shell"
            fi
        else
            print_status "yellow" "Original shell not found, using system default..."
            DEFAULT_SHELL=$(get_original_shell)
            sudo chsh -s "$DEFAULT_SHELL" "$USER"
            if [ $? -eq 0 ]; then
                print_status "green" "Restored default shell: $DEFAULT_SHELL"
                rm -f ~/.nosh_backup 2>/dev/null || sudo rm -f ~/.nosh_backup
            fi
        fi
    fi
    
    # Remove from shells list
    if grep -q "nosh" /etc/shells; then
        sudo sed -i.bak '/nosh/d' /etc/shells
        sudo rm -f /etc/shells.bak
    fi
    
    # Remove nosh binary and related files
    if [[ -f /usr/local/bin/nosh ]]; then
        sudo rm -f /usr/local/bin/nosh
    fi
    
    # Clean up build directory
    if [[ -d build ]]; then
        rm -rf build
    fi
    
    # Clean up configuration files
    if [[ -d ~/.nosh ]]; then
        read -p "Do you want to remove nosh configuration files? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf ~/.nosh 2>/dev/null || sudo rm -rf ~/.nosh
            print_status "green" "Removed nosh configuration files"
        fi
    fi
    
    # Final cleanup of any remaining files
    rm -f ~/.nosh_backup 2>/dev/null || sudo rm -f ~/.nosh_backup
    
    print_status "green" "nosh has been uninstalled"
}

# Function to handle recompilation
handle_recompile() {
    print_status "yellow" "Recompiling nosh..."
    rm -rf build
    build_only
}

# Function to handle shell settings
handle_shell_settings() {
    clear
    print_status "green" "Shell Settings"
    
    # Different menu based on whether nosh is installed
    if command_exists nosh || [[ -f /usr/local/bin/nosh ]]; then
        echo "1. Make nosh default shell"
        echo "2. Restore original shell"
        echo "3. Back to main menu"
        echo
        read -p "Please select an option [1-3]: " choice
        
        case $choice in
            1) make_default_shell ;;
            2) restore_original_shell ;;
            3) 
                if command_exists nosh || [[ -f /usr/local/bin/nosh ]]; then
                    show_menu
                else
                    show_install_menu
                fi
                ;;
            *) 
                print_status "red" "Invalid option"
                sleep 2
                handle_shell_settings
                ;;
        esac
    else
        print_status "red" "nosh is not installed"
        sleep 2
        show_install_menu
    fi
}

# Function to get original shell
get_original_shell() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS specific way to get user shell
        ORIG_SHELL=$(dscl . -read /Users/$USER UserShell | sed 's/UserShell: //')
    else
        # Linux way using getent
        ORIG_SHELL=$(getent passwd "$USER" | cut -d: -f7)
    fi
    
    # Fallback to $SHELL if previous methods fail
    if [ -z "$ORIG_SHELL" ]; then
        ORIG_SHELL="$SHELL"
    fi
    
    # Final fallback to common shells
    if [ -z "$ORIG_SHELL" ]; then
        for shell in /bin/bash /bin/zsh /bin/sh; do
            if [ -x "$shell" ]; then
                ORIG_SHELL="$shell"
                break
            fi
        done
    fi
    
    echo "$ORIG_SHELL"
}

# Update make_default_shell function
make_default_shell() {
    if [[ ! -x /usr/local/bin/nosh ]]; then
        print_status "red" "nosh is not installed in /usr/local/bin"
        return 1
    fi

    # Backup current shell if not already backed up
    if [[ ! -f ~/.nosh_backup ]]; then
        ORIG_SHELL=$(get_original_shell)
        if [ -n "$ORIG_SHELL" ]; then
            echo "$ORIG_SHELL" > ~/.nosh_backup
            print_status "yellow" "Backed up original shell: $ORIG_SHELL"
        else
            print_status "red" "Could not determine original shell"
            return 1
        fi
    fi

    # Add nosh to /etc/shells if not already there
    if ! grep -q "^/usr/local/bin/nosh$" /etc/shells; then
        print_status "yellow" "Adding nosh to /etc/shells..."
        echo "/usr/local/bin/nosh" | sudo tee -a /etc/shells
    fi

    # Set nosh as default shell
    sudo chsh -s "/usr/local/bin/nosh" "$USER"
    if [ $? -eq 0 ]; then
        print_status "green" "Changed default shell to nosh"
        print_status "yellow" "Please log out and back in for the change to take effect"
    else
        print_status "red" "Failed to change shell"
        return 1
    fi
}

# Function to restore original shell
restore_original_shell() {
    if [[ -f ~/.nosh_backup ]]; then
        ORIG_SHELL=$(cat ~/.nosh_backup)
        sudo chsh -s "$ORIG_SHELL" "$USER"
        rm ~/.nosh_backup
        print_status "green" "Restored original shell: $ORIG_SHELL"
    else
        print_status "red" "No shell backup found"
    fi
}

# Function to install dependencies on macOS
install_macos_deps() {
    print_status "yellow" "Installing dependencies using Homebrew..."
    
    if ! command_exists brew; then
        print_status "red" "Homebrew is not installed. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install \
        readline \
        openssl \
        mbedtls \
        argon2 \
        pkg-config \
        cmake
}

# Function to install dependencies on Linux
install_linux_deps() {
    print_status "yellow" "Installing dependencies..."
    
    if command_exists apt-get; then
        print_status "green" "Debian/Ubuntu detected"
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            libreadline-dev \
            libmbedtls-dev \
            libargon2-dev \
            pkg-config \
            cmake

    elif command_exists dnf; then
        print_status "green" "Fedora/RHEL detected"
        sudo dnf install -y \
            gcc \
            gcc-c++ \
            readline-devel \
            mbedtls-devel \
            libargon2-devel \
            pkgconfig \
            cmake

    elif command_exists pacman; then
        print_status "green" "Arch Linux detected"
        sudo pacman -Syu --noconfirm \
            base-devel \
            readline \
            mbedtls \
            argon2 \
            pkgconf \
            cmake

    elif command_exists zypper; then
        print_status "green" "openSUSE detected"
        sudo zypper install -y \
            gcc \
            gcc-c++ \
            readline-devel \
            mbedtls-devel \
            libargon2-devel \
            pkg-config \
            cmake

    elif command_exists emerge; then
        print_status "green" "Gentoo detected"
        sudo emerge --ask=n \
            sys-libs/readline \
            net-libs/mbedtls \
            app-crypt/argon2 \
            dev-util/pkgconf \
            dev-util/cmake

    elif command_exists xbps-install; then
        print_status "green" "Void Linux detected"
        sudo xbps-install -Sy \
            base-devel \
            readline-devel \
            mbedtls-devel \
            libargon2-devel \
            pkg-config \
            cmake

    else
        print_status "red" "Unsupported Linux distribution"
        print_status "yellow" "Please install the following packages manually:"
        echo "- C compiler (GCC or Clang)"
        echo "- GNU Readline development files"
        echo "- mbed TLS development files"
        echo "- Argon2 development files"
        echo "- pkg-config"
        echo "- CMake"
        exit 1
    fi
}

# Function to only build without installing
build_only() {
    mkdir -p build
    cd build || exit 1
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        cmake .. -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_PREFIX_PATH="$(brew --prefix)" \
            -DMBEDTLS_ROOT_DIR=$(brew --prefix mbedtls) \
            -DARGON2_ROOT_DIR=$(brew --prefix argon2) \
            -DCMAKE_FIND_FRAMEWORK=LAST \
            -DCMAKE_INSTALL_NAME_DIR=@executable_path/../lib \
            -DCMAKE_BUILD_WITH_INSTALL_NAME_DIR=ON \
            -DCMAKE_LIBRARY_PATH="/usr/local/lib" \
            -DCMAKE_INCLUDE_PATH="/usr/local/include" \
            -DCMAKE_EXE_LINKER_FLAGS="-L/usr/local/lib"
        
        if [[ $(uname -m) == "arm64" ]]; then
            cmake .. -DCMAKE_OSX_ARCHITECTURES=arm64
        fi
    else
        cmake .. -DCMAKE_BUILD_TYPE=Release
    fi
    
    make
}

# Update build_and_install function
function build_and_install() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        print_status "green" "macOS detected"
        install_macos_deps
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_status "green" "Linux detected"
        install_linux_deps
    else
        print_status "red" "Unsupported operating system"
        exit 1
    fi
    
    build_only
    
    if [ $? -eq 0 ]; then
        print_status "green" "Build completed successfully!"
        
        # When NO_INTERACTION is 1, install and set shell automatically
        if [ $NO_INTERACTION -eq 1 ]; then
            sudo make install
            print_status "green" "nosh has been installed to /usr/local/bin"
            make_default_shell
            print_status "yellow" "Installation complete. You can now run 'nosh' from any terminal."
            return 0
        fi

        # Interactive mode
        read -p "Would you like to install nosh to /usr/local/bin? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo make install
            print_status "green" "nosh has been installed to /usr/local/bin"
            
            read -p "Would you like to make nosh your default shell? (y/N) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                make_default_shell
            fi
            
            print_status "yellow" "Installation complete. You can now run 'nosh' from any terminal."
            read -p "Press Enter to return to menu..."
            show_menu
        else
            print_status "yellow" "nosh executable can be found in the build directory"
            read -p "Press Enter to return to menu..."
            show_install_menu
        fi
    else
        print_status "red" "Build failed"
        exit 1
    fi
}

# Function to show installation menu
show_install_menu() {
    clear
    print_status "green" "NOSH Installation Menu"
    
    # Base menu items
    echo "1. Install nosh"
    echo "2. Compile only (without installing)"
    echo "3. Show build requirements"
    
    # Check if we're on macOS and Homebrew is not installed
    if [[ "$OSTYPE" == "darwin"* ]] && ! command_exists brew; then
        echo "4. Install Homebrew"
        echo "5. Change shell settings"
        echo "6. Exit"
        echo
        read -p "Please select an option [1-6]: " choice
        
        case $choice in
            1) build_and_install ;;
            2) build_only ;;
            3) show_requirements ;;
            4) install_homebrew ;;
            5) handle_shell_settings ;;
            6) exit 0 ;;
            *) 
                print_status "red" "Invalid option"
                sleep 2
                show_install_menu
                ;;
        esac
    else
        echo "4. Change shell settings"
        echo "5. Exit"
        echo
        read -p "Please select an option [1-5]: " choice
        
        case $choice in
            1) build_and_install ;;
            2) build_only ;;
            3) show_requirements ;;
            4) handle_shell_settings ;;
            5) exit 0 ;;
            *) 
                print_status "red" "Invalid option"
                sleep 2
                show_install_menu
                ;;
        esac
    fi
}

# Add Homebrew installation function
install_homebrew() {
    print_status "yellow" "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    if command_exists brew; then
        print_status "green" "Homebrew installed successfully"
    else
        print_status "red" "Failed to install Homebrew"
    fi
    
    read -p "Press Enter to return to menu..."
    show_install_menu
}

# Function to show requirements
show_requirements() {
    clear
    print_status "green" "NOSH Build Requirements"
    echo
    print_status "yellow" "Required Dependencies:"
    echo "- C compiler (GCC or Clang)"
    echo "- GNU Readline development files"
    echo "- mbed TLS development files"
    echo "- Argon2 development files"
    echo "- pkg-config"
    echo "- CMake"
    echo
    print_status "yellow" "Platform-specific package names:"
    echo
    echo "Debian/Ubuntu:"
    echo "  sudo apt-get install build-essential libreadline-dev libmbedtls-dev libargon2-dev pkg-config cmake"
    echo
    echo "macOS (Homebrew):"
    echo "  brew install readline openssl mbedtls argon2 pkg-config cmake"
    echo
    echo "Arch Linux:"
    echo "  sudo pacman -S base-devel readline mbedtls argon2 pkgconf cmake"
    echo
    read -p "Press Enter to return to menu..."
    show_install_menu
}

# Add help function
show_help() {
    echo "NOSH Manager - Installation and Management Script"
    echo
    echo "Usage: ./nosh-manager.sh [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -i, --install           Install nosh with default settings"
    echo "  -c, --compile           Compile nosh without installing"
    echo "  -u, --uninstall         Uninstall nosh"
    echo "  -r, --requirements      Show build requirements"
    echo "  -d, --default-shell     Make nosh the default shell"
    echo "  -s, --restore-shell     Restore original shell"
    echo "  -n, --network           Install from network (git)"
    echo "  -y, --yes              Automatic yes to prompts"
    echo "  --no-interaction        Run without user interaction"
    echo
    echo "Examples:"
    echo "  ./nosh-manager.sh --install --no-interaction"
    echo "  ./nosh-manager.sh --install -y -d"
    echo "  ./nosh-manager.sh --network --no-interaction"
    echo "  ./nosh-manager.sh -c"
    echo "  ./nosh-manager.sh --uninstall"
}

# Add network installation function
install_from_network() {
    clear
    print_status "green" "Network Installation"
    
    if ! command_exists git; then
        print_status "red" "Git is not installed. Please install git first."
        exit 1
    fi

    # Default values
    REPO_URL="https://github.com/Dynamicaaa/nosh.git"
    BRANCH="main"

    if [ $NO_INTERACTION -eq 0 ]; then
        read -p "Enter branch name [main]: " branch_input
        if [ -n "$branch_input" ]; then
            BRANCH="$branch_input"
        fi
    fi

    print_status "yellow" "Cloning nosh from $REPO_URL branch: $BRANCH..."
    
    # Create temporary directory
    TMP_DIR=$(mktemp -d)
    cd "$TMP_DIR" || exit 1

    # Clone repository
    if git clone -b "$BRANCH" "$REPO_URL" .; then
        print_status "green" "Repository cloned successfully"
        
        # Build and install
        if [ $NO_INTERACTION -eq 1 ]; then
            NO_INTERACTION=1 ./nosh-manager.sh --install
        else
            ./nosh-manager.sh
        fi
    else
        print_status "red" "Failed to clone repository"
        exit 1
    fi

    # Cleanup
    cd - > /dev/null
    rm -rf "$TMP_DIR"
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                HELP_FLAG=1
                shift
                ;;
            -i|--install)
                INSTALL_FLAG=1
                shift
                ;;
            -c|--compile)
                COMPILE_FLAG=1
                shift
                ;;
            -u|--uninstall)
                UNINSTALL_FLAG=1
                shift
                ;;
            -r|--requirements)
                REQUIREMENTS_FLAG=1
                shift
                ;;
            -d|--default-shell)
                DEFAULT_SHELL_FLAG=1
                shift
                ;;
            -s|--restore-shell)
                RESTORE_SHELL_FLAG=1
                shift
                ;;
            -n|--network)
                NETWORK_FLAG=1
                shift
                ;;
            -y|--yes)
                YES_FLAG=1
                NO_INTERACTION=1
                shift
                ;;
            --no-interaction)
                NO_INTERACTION=1
                shift
                ;;
            *)
                print_status "red" "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Now act on the flags in a defined order.
    if [[ $HELP_FLAG -eq 1 ]]; then
        show_help
        exit 0
    fi

    if [[ $NETWORK_FLAG -eq 1 ]]; then
        install_from_network
        exit 0
    fi

    if [[ $UNINSTALL_FLAG -eq 1 ]]; then
        handle_uninstall
        exit 0
    fi

    if [[ $COMPILE_FLAG -eq 1 ]]; then
        build_only
        exit 0
    fi

    if [[ $REQUIREMENTS_FLAG -eq 1 ]]; then
        show_requirements
        exit 0
    fi

    if [[ $DEFAULT_SHELL_FLAG -eq 1 ]]; then
        make_default_shell
        exit 0
    fi

    if [[ $RESTORE_SHELL_FLAG -eq 1 ]]; then
        restore_original_shell
        exit 0
    fi

    if [[ $INSTALL_FLAG -eq 1 ]]; then
        # New check: If running in no-interaction mode, ensure the script is running as root.
        if [[ $NO_INTERACTION -eq 1 ]]; then
            if [ "$(id -u)" -ne 0 ]; then
                print_status "red" "Error: --install --no-interaction must be run as root (or via sudo). Aborting installation."
                exit 1
            fi
        fi
        build_and_install
        exit 0
    fi

    # If no flags were provided, show the interactive menu.
    if [[ $NO_INTERACTION -eq 0 ]]; then
        print_status "green" "NOSH - Network Oriented Security Shell Manager"
        print_status "yellow" "Checking installation status..."
        
        if command_exists nosh || [[ -f /usr/local/bin/nosh ]]; then
            print_status "yellow" "nosh is already installed"
            show_menu
        else
            print_status "yellow" "nosh is not installed"
            show_install_menu
        fi
    fi
}

# Run main installation
main "$@"