# Project paths
client := "client"
driver := "driver"

alias c := clean
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

# Default task: build workspace and update dependencies
default:
    just client
    just driver

# Build the entire workspace (includes client + common + shadowx)
client:
    cd {{ client }}; cargo build --release

# Build only client-mapper (if it's a separate feature)
client-mapper:
    cd {{ client }}; cargo build --release --features mapper

# Build the driver (outside workspace)
driver:
    @if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { \
        throw "[-] You must run this as Administrator"; \
    } \
    cd {{ driver }}; cargo make default --release

# Build the driver with `mapper` feature
driver-mapper:
    @if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { \
        throw "[-] You must run this as Administrator"; \
    } \
    cd {{ driver }}; cargo make default --release --features mapper

# Clean everything in the workspace
clean:
    cargo clean
    cd {{ client }}; cargo clean
    cd {{ driver }}; cargo clean

# Update the entire workspace (client + common + shadowx)
update:
    cargo update
