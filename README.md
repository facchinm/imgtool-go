# imgtool (Go)

A single static binary rewrite of MCUboot's `scripts/imgtool.py`, using only the Go standard library.
Output is byte-compatible with upstream (verified for Ed25519, which signs deterministically; RSA/ECDSA
images cross-verify in both directions).

    go build -o imgtool .
    ./imgtool keygen -t ecdsa-p256 -k key.pem
    ./imgtool sign -k key.pem -v 1.0.0 -H 0x200 --pad-header -S 0x20000 --pad --confirm app.bin signed.bin
    ./imgtool verify -k key.pem signed.bin
    ./imgtool dumpinfo signed.bin

## Commands
`keygen`, `getpub`, `getpubhash`, `keyinfo`, `sign` (alias `create`), `verify`, `dumpinfo` (human/json), `version`.

Supported keys: RSA-2048/3072 (PSS), ECDSA P-256/P-384, Ed25519 (incl. `--pure`).
`sign` supports: `.bin`/`.hex` I/O, header/padding/trailer options (`--pad`, `--confirm`, `--test`,
`--overwrite-only`, `--align`, `--max-align`, `-M`, `-R`), endianness, `--sha`, security counter,
dependencies, `--vid/--cid`, custom TLVs, `--public-key-format`, `--fix-sig`/`--sig-out`, `--vector-to-sign`.

## Not implemented (vs. upstream)
Image encryption (`-E`, X25519 keys), LZMA compression, `--boot-record`, password-protected keys,
`getpriv`, YAML output in `dumpinfo`. Using these options returns an explicit error.
Options use Go `flag` syntax: `-v 1.0` / `--version 1.0` (short flags can't be combined).
