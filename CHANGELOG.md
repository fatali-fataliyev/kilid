# Changelog

## [1.0.0] - 2026-03-26

### Added

- CLI commands
- Implemented core features
- `-d` and `-y` advanced flags

---

## [2.0.0] - 2026-04-11

### Breaking Changes

- **File Compatibility:** Files created with version **1.0.0** are no longer supported due to a change in the underlying data structure.

### Added

- **Large File Support**: Efficient stream-processing handles files of any size with minimal RAM usage.
- **Concurrent Processing**: Encrypt and decrypt multiple files simultaneously.
- **Live UI**: Real-time multi-file progress bars powered by [mbp](https://github.com/vbauerster/mpb).

### Fixed

- Various bug fixes and performance optimizations.

---

## [3.0.0] - 2026-04-20

### Breaking Changes

- **File Compatibility:** Files created with version **2.0.0** or older are no longer supported due to a change in the underlying data structure.

### Security

- Switched to Argon2id (replacing SHA-256) for superior brute-force and rainbow table resistance.

### Added

- `version or v` command to display current version.
- Password confirmation prompt to prevent typos.
- Added `-wipe` flag to **Encryption** command for secure file shredding, overwrites original data with random bytes to prevent recovery.
- Added `-output` flag to **info** command for write info in a file.
- Added ETA to bars for tracking estimated complete time.

### Fixed

- Fixed bug causing log erasure.
- Fixed bug causing the progress bar to freeze.
- Fixed empty file creation on failed encryption or decryption operations.
