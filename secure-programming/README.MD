# Offline Password Manager

A cross-platform, single-user, offline CLI password-manager project for a secure-programming course.

## Scope

Planned: one master password unlocks one locally stored, versioned encrypted vault; create, list, retrieve, update and delete credential entries; change master password; explicitly lock or quit. See [architecture, threat model, vault format, and crypto choices](docs/DESIGN.md).

## Planned commands (not implemented)

```text
pm init [--vault PATH]                    # create encrypted vault; prompt for master password
pm add [--vault PATH]                     # prompt for account fields and secret
pm list [--vault PATH]                    # list entry labels after unlock
pm get LABEL [--vault PATH]               # explicitly display an entry after unlock
pm update LABEL [--vault PATH]            # change an entry
pm delete LABEL [--vault PATH]            # remove an entry
pm change-master [--vault PATH]           # re-encrypt under a new master password
pm help                                   # show usage
pm lock                                   # lock vault
pm unlock                                 # unlock vault
```

All commands that use a vault will prompt interactively for the master password without echo; it must **not** be supplied through command arguments. Command spellings and flags are a W.I.P.

## Build and run

Requirements: gcc and CMake (version TBD depending on what language features I end up using).
```sh
cmake -S . -B build # Initial config after projects install, kind of like npm install
cmake --build build
```

Run the program:

```sh
# MacOS
./build/pm
# Windows
.\build\pm.exe
```

## External dependency justification

**libsodium** provides portable C APIs for Argon2id password-based key derivation, XChaCha20-Poly1305 authenticated encryption, secure random bytes and sensitive-memory cleanup.

**CMake** is a build tool that is convinient for cross-platform
