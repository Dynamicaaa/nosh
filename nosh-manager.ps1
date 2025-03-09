# NOSH Manager PowerShell Script

# Global variables
$NoInteraction = $false
$ErrorActionPreference = "Stop"

# Function to print colored status messages
function Write-Status {
    param (
        [string]$Color,
        [string]$Message
    )
    
    switch ($Color) {
        "green" { Write-Host $Message -ForegroundColor Green }
        "red" { Write-Host $Message -ForegroundColor Red }
        "yellow" { Write-Host $Message -ForegroundColor Yellow }
        default { Write-Host $Message }
    }
}

# Function to check if a command exists
function Test-Command {
    param ([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# Function to install dependencies using MSYS2
function Install-Dependencies {
    Write-Status "yellow" "Installing dependencies using MSYS2..."
    
    if (-not (Test-Command "pacman")) {
        Write-Status "red" "MSYS2 is not installed. Please install it from https://www.msys2.org/"
        exit 1
    }

    # Update MSYS2
    pacman -Syu --noconfirm
    pacman -Su --noconfirm

    # Install required packages
    pacman -S --needed --noconfirm `
        mingw-w64-x86_64-gcc `
        mingw-w64-x86_64-cmake `
        mingw-w64-x86_64-make `
        mingw-w64-x86_64-mbedtls `
        mingw-w64-x86_64-argon2 `
        mingw-w64-x86_64-pkgconf `
        mingw-w64-x86_64-readline `
        mingw-w64-x86_64-windows-default-manifest `
        mingw-w64-x86_64-ncurses `
        mingw-w64-x86_64-pdcurses
}

# Function to build nosh
function Build-Nosh {
    if (-not (Test-Path "build")) {
        New-Item -ItemType Directory -Path "build" | Out-Null
    }
    Push-Location "build"

    try {
        cmake .. -G "MinGW Makefiles" `
            -DCMAKE_BUILD_TYPE=Release `
            -DCMAKE_C_COMPILER=/mingw64/bin/gcc.exe `
            -DCMAKE_MAKE_PROGRAM=/mingw64/bin/mingw32-make.exe `
            -DCMAKE_C_FLAGS="-D_GNU_SOURCE -D_WIN32 -DWIN32_LEAN_AND_MEAN" `
            -DCMAKE_PREFIX_PATH=/mingw64 `
            -DCMAKE_LIBRARY_PATH=/mingw64/lib `
            -DCMAKE_INCLUDE_PATH="/mingw64/include;/mingw64/include/readline" `
            -DREADLINE_ROOT=/mingw64 `
            -DCMAKE_EXE_LINKER_FLAGS="-static-libgcc -static-libstdc++ -Wl,-Bstatic -lpdcurses -lreadline -lmbedtls -lmbedcrypto -lmbedx509 -largon2 -Wl,-Bdynamic -lws2_32 -liphlpapi -lbcrypt"

        mingw32-make
    }
    finally {
        Pop-Location
    }
}

# Function to install nosh
function Install-Nosh {
    $targetDir = "$env:USERPROFILE\AppData\Local\Programs\nosh"
    
    # Create installation directory
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir | Out-Null
    }

    # Copy executable
    Copy-Item "build\nosh.exe" -Destination "$targetDir\nosh.exe" -Force

    # Add to PATH if not already there
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$targetDir*") {
        [Environment]::SetEnvironmentVariable(
            "Path",
            "$userPath;$targetDir",
            "User"
        )
        Write-Status "yellow" "Added nosh to user PATH. Please restart your terminal."
    }

    Write-Status "green" "nosh has been installed to: $targetDir"
}

# Function to uninstall nosh
function Uninstall-Nosh {
    Write-Status "yellow" "Uninstalling nosh..."

    # Remove from PATH
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $targetDir = "$env:USERPROFILE\AppData\Local\Programs\nosh"
    if ($userPath -like "*$targetDir*") {
        $newPath = ($userPath -split ';' | Where-Object { $_ -ne $targetDir }) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    }

    # Remove installation directory
    if (Test-Path $targetDir) {
        Remove-Item -Path $targetDir -Recurse -Force
    }

    # Remove configuration
    $configDir = "$env:USERPROFILE\.nosh"
    if (Test-Path $configDir) {
        $response = Read-Host "Do you want to remove nosh configuration files? (y/N)"
        if ($response -eq 'y') {
            Remove-Item -Path $configDir -Recurse -Force
            Write-Status "green" "Removed nosh configuration files"
        }
    }

    Write-Status "green" "nosh has been uninstalled"
}

# Function to show requirements
function Show-Requirements {
    Clear-Host
    Write-Status "green" "NOSH Build Requirements"
    Write-Host ""
    Write-Status "yellow" "Required Dependencies:"
    Write-Host "- MSYS2 (with MinGW-w64)"
    Write-Host "- GCC (through MSYS2)"
    Write-Host "- CMake"
    Write-Host "- GNU Readline"
    Write-Host "- mbed TLS"
    Write-Host "- Argon2"
    Write-Host "- pkg-config"
    Write-Host ""
    Write-Status "yellow" "Installation Instructions:"
    Write-Host "1. Install MSYS2 from https://www.msys2.org/"
    Write-Host "2. Open MSYS2 MinGW 64-bit shell"
    Write-Host "3. Run the following command:"
    Write-Host "   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-make mingw-w64-x86_64-mbedtls mingw-w64-x86_64-argon2 mingw-w64-x86_64-pkgconf mingw-w64-x86_64-readline"
    Write-Host ""
    Read-Host "Press Enter to return to menu"
}

# Function to show help
function Show-Help {
    Write-Host "NOSH Manager - Installation and Management Script"
    Write-Host ""
    Write-Host "Usage: .\nosh-manager.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Help              Show this help message"
    Write-Host "  -Install           Install nosh with default settings"
    Write-Host "  -Compile           Compile nosh without installing"
    Write-Host "  -Uninstall         Uninstall nosh"
    Write-Host "  -Requirements      Show build requirements"
    Write-Host "  -NoInteraction     Run without user interaction"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\nosh-manager.ps1 -Install -NoInteraction"
    Write-Host "  .\nosh-manager.ps1 -Compile"
    Write-Host "  .\nosh-manager.ps1 -Uninstall"
}

# Main menu function
function Show-MainMenu {
    Clear-Host
    Write-Status "green" "NOSH Management Menu"
    Write-Host "1. Install nosh"
    Write-Host "2. Compile only"
    Write-Host "3. Uninstall nosh"
    Write-Host "4. Show requirements"
    Write-Host "5. Exit"
    Write-Host ""
    
    $choice = Read-Host "Please select an option [1-5]"
    
    switch ($choice) {
        "1" { 
            Install-Dependencies
            Build-Nosh
            Install-Nosh
        }
        "2" { 
            Install-Dependencies
            Build-Nosh
        }
        "3" { Uninstall-Nosh }
        "4" { Show-Requirements }
        "5" { exit 0 }
        default {
            Write-Status "red" "Invalid option"
            Start-Sleep -Seconds 2
            Show-MainMenu
        }
    }
}

# Parse command line arguments
param(
    [switch]$Help,
    [switch]$Install,
    [switch]$Compile,
    [switch]$Uninstall,
    [switch]$Requirements,
    [switch]$NoInteraction
)

if ($Help) { Show-Help; exit 0 }
if ($NoInteraction) { $script:NoInteraction = $true }

if ($Install) {
    Install-Dependencies
    Build-Nosh
    Install-Nosh
    exit 0
}
if ($Compile) {
    Install-Dependencies
    Build-Nosh
    exit 0
}
if ($Uninstall) {
    Uninstall-Nosh
    exit 0
}
if ($Requirements) {
    Show-Requirements
    exit 0
}

# If no arguments, show interactive menu
Write-Status "green" "NOSH - Network Oriented Security Shell Manager"
Write-Status "yellow" "Checking installation status..."

$noshInstalled = Test-Path "$env:USERPROFILE\AppData\Local\Programs\nosh\nosh.exe"
if ($noshInstalled) {
    Write-Status "yellow" "nosh is already installed"
} else {
    Write-Status "yellow" "nosh is not installed"
}

Show-MainMenu