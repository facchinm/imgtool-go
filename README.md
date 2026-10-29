# imgtool (Go)

A single static binary rewrite of MCUboot's `scripts/imgtool.py`, using only the Go standard library.
Output is byte-compatible with upstream for unencrypted/uncompressed images (verified for Ed25519, which signs
deterministically; RSA/ECDSA images cross-verify in both directions).

    go build -o imgtool .
    ./imgtool keygen -t ecdsa-p256 -k key.pem
    ./imgtool sign -k key.pem -v 1.0.0 -H 0x200 --pad-header -S 0x20000 --pad --confirm app.bin signed.bin
    ./imgtool verify -k key.pem signed.bin
    ./imgtool dumpinfo signed.bin

## Commands
`keygen`, `getpriv`, `getpub`, `getpubhash`, `keyinfo`, `sign` (alias `create`), `verify`, `dumpinfo` (human/json), `version`.

Supported keys: RSA-2048/3072 (PSS), ECDSA P-256/P-384, Ed25519 (incl. `--pure`); X25519 for encryption.
`sign` supports: `.bin`/`.hex` I/O, header/padding/trailer options (`--pad`, `--confirm`, `--test`,
`--overwrite-only`, `--align`, `--max-align`, `-M`, `-R`), endianness, `--sha`, security counter,
dependencies, `--vid/--cid`, custom TLVs, `--public-key-format`, `--fix-sig`/`--sig-out`, `--vector-to-sign`.
Compression: `--compression lzma2|lzma2armthumb` (raw LZMA2, dict 128 KiB, lc=3 lp=1 pb=2, optional ARM-Thumb BCJ
filter); falls back to an uncompressed image if it doesn't shrink. Streams decode with liblzma but are ~10% larger
than liblzma's (pure-Go encoder), so they are not byte-identical to upstream.
Encryption: `-E <pubkey>` (RSA-OAEP, ECIES-P256, ECIES-X25519), `--encrypt-keylen 128|256`,
`--hmac-sha 256|512` (X25519), `-c/--clear`, `--save-enctlv`.

## Differences from upstream
- If compression doesn't shrink the image, the fallback image is built normally (upstream would emit an
  unencrypted image flagged as encrypted when `-E` is used). The slot-size check only applies to the final image.
- `--non-bootable` is preserved on compressed images.

## Not implemented
`--boot-record`, password-protected keys, YAML output in `dumpinfo`. Using these options returns an explicit error.
Options use Go `flag` syntax: `-v 1.0` / `--version 1.0` (short flags can't be combined).
