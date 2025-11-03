# elkssl
## Mbed TLS for the ELKS 16-bit environment

`elkssl` is a curated subset of Mbed TLS 2.29 tailored for the ELKS protected-mode/OpenWatcom toolchain. It produces a static library that fits within the ELKS memory and compiler constraints while preserving a modern TLS 1.2 client stack (RSA key exchange, AES-CBC record protection, SHA-1/SHA-256 digests, X.509 certificate parsing).

### Layout
- `Project/` – single-level copy of the required Mbed TLS sources configured for ELKS.
- `build-elks-elkssl.sh` – OpenWatcom build entry point; emits `build-elks/lib/elkssl.lib` plus staged headers under `build-elks/include/`.
- Legacy Mac-specific artefacts from the upstream prototype remain for reference only and are not part of the ELKS build.

### Building
```bash
source ../env.sh          # establishes TOPDIR and tool paths
./build-elks-elkssl.sh    # compiles and archives elkssl.lib
```

The script automatically selects the Watcom memory model defined in `libc/watcom.model`, compiles the curated Mbed TLS sources with `wcc`, and archives them with `wlib`. Intermediate object files are discarded so only the library and exported headers remain in `build-elks/`.

### Configuration
`Project/config.h` trims the upstream configuration to operate within ELKS limits:
- Disables assembler and 64-bit arithmetic assumptions.
- Keeps TLS 1.2 client mode, RSA key exchange, AES-CBC, SHA-1/SHA-256, and X.509 parsing.
- Leverages ELKS libc directly for memory allocation and formatted I/O (`calloc`, `free`, `printf`, `snprintf`).
- Provides a placeholder `mbedtls_hardware_poll` implementation in `entropy_elks.c`; replace with a genuine entropy source on real hardware.

### Next steps
- Link `build-elks/lib/elkssl.lib` into an ELKS networking application and confirm a TLS handshake.
- Swap in a hardware-backed entropy collector.
- Extend the configuration if additional cipher suites or key exchanges become necessary.
