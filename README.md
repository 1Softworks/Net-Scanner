# Network Scanner

A lightweight C++ network scanner that discovers active hosts on your local network. It provides IP addresses, hostnames, and MAC addresses of connected devices.

## Features

- Fast multi-threaded scanning of entire subnet
- Detects active hosts using ICMP ping
- Resolves hostnames via DNS lookup
- Retrieves MAC addresses of discovered devices
- Clean console output formatting

## Requirements

- Linux operating system
- Root/sudo privileges (required for raw socket operations)
- C++ compiler with C++11 support
- Standard Linux networking libraries
