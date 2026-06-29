# ProtonVPN Server Cache

The VPN IP collector can read ProtonVPN server data from a local client cache binary.

## How to obtain the cache file

1. Install and run the ProtonVPN desktop client (Windows or Linux)
2. Connect at least once so the server list is cached
3. Copy the cache file to this directory

### Windows

```
%LOCALAPPDATA%\Proton\Proton VPN\Storage\Servers.*.bin
```

### Linux

```
~/.local/share/protonvpn/**/Servers.*.bin
~/.config/protonvpn/**/Servers.*.bin
```

## Naming convention

- `Servers.current.bin` — preferred name; the collector checks for this first
- `Servers.{hash}.bin` — also accepted (original filename from the client)

## Why this exists

ProtonVPN's API requires authentication (SRP-based), so there is no public
endpoint to fetch the server list. The local client cache is the only viable
source without storing credentials. In CI, if no cache is present here, the
ProtonVPN provider is skipped with a warning.
