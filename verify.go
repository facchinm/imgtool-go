package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
)

type VerifyResult int

const (
	VerifyOK VerifyResult = iota
	VerifyInvalidMagic
	VerifyInvalidTLVInfoMagic
	VerifyInvalidHash
	VerifyInvalidSignature
	VerifyKeyMismatch
)

func readImageFile(path string) ([]byte, error) {
	if strings.EqualFold(filepath.Ext(path), ".hex") {
		h, err := ReadHex(path)
		if err != nil {
			return nil, err
		}
		return h.Binary(), nil
	}
	return os.ReadFile(path)
}

func tlvSHA(t uint16) (string, bool) {
	switch t {
	case tlvSHA256:
		return "256", true
	case tlvSHA384:
		return "384", true
	case tlvSHA512:
		return "512", true
	}
	return "", false
}

func keyAllowsSHA(key *Key, sha string) bool {
	if key == nil {
		return true
	}
	for _, a := range key.AllowedSHA(false) {
		if a == sha {
			return true
		}
	}
	return false
}

// VerifyImage validates the image hash and, if key is given, its signature.
func VerifyImage(path string, key *Key) (res VerifyResult, ver Version, digest, sig []byte, err error) {
	b, err := readImageFile(path)
	if err != nil {
		return 0, ver, nil, nil, err
	}
	if len(b) < imageHeaderSize {
		return VerifyInvalidMagic, ver, nil, nil, nil
	}
	le := binary.LittleEndian
	if le.Uint32(b[0:]) != imageMagic {
		return VerifyInvalidMagic, ver, nil, nil, nil
	}
	hdrSize, imgSize := int(le.Uint16(b[8:])), int(le.Uint32(b[12:]))
	ver = Version{uint16(b[20]), uint16(b[21]), le.Uint16(b[22:]), le.Uint32(b[24:])}

	off := hdrSize + imgSize
	if off+tlvInfoSize > len(b) {
		return VerifyInvalidTLVInfoMagic, ver, nil, nil, nil
	}
	magic, tot := le.Uint16(b[off:]), int(le.Uint16(b[off+2:]))
	if magic == tlvProtInfoMagic {
		off += tot
		if off+tlvInfoSize > len(b) {
			return VerifyInvalidTLVInfoMagic, ver, nil, nil, nil
		}
		magic, tot = le.Uint16(b[off:]), int(le.Uint16(b[off+2:]))
	}
	if magic != tlvInfoMagic || off+tot > len(b) {
		return VerifyInvalidTLVInfoMagic, ver, nil, nil, nil
	}

	hashRegion := b[:off]
	end := off + tot
	type rec struct {
		typ uint8
		val []byte
	}
	var recs []rec
	pure := false
	for p := off + tlvInfoSize; p+tlvSize <= end; {
		t, l := b[p], int(le.Uint16(b[p+2:]))
		if p+tlvSize+l > end {
			break
		}
		recs = append(recs, rec{t, b[p+tlvSize : p+tlvSize+l]})
		if t == tlvSigPure {
			pure = true
		}
		p += tlvSize + l
	}

	for _, r := range recs {
		if sha, ok := tlvSHA(uint16(r.typ)); ok {
			if !keyAllowsSHA(key, sha) {
				return VerifyKeyMismatch, ver, nil, nil, nil
			}
			digest = digestOf(sha, hashRegion)
			if !bytes.Equal(digest, r.val) {
				return VerifyInvalidHash, ver, nil, nil, nil
			}
			if key == nil {
				return VerifyOK, ver, digest, nil, nil
			}
		} else if key != nil && !pure && r.typ == key.SigTLV() {
			if key.Verify(r.val, hashRegion, digest, false) {
				return VerifyOK, ver, digest, nil, nil
			}
		} else if key != nil && pure && r.typ == tlvED25519 {
			if key.Kind == KindEd25519 && key.Verify(r.val, hashRegion, nil, true) {
				return VerifyOK, ver, nil, r.val, nil
			}
		}
	}
	return VerifyInvalidSignature, ver, nil, nil, nil
}
