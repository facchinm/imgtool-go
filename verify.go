package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type dumpTLV struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Length    int    `json:"length"`
	Value     string `json:"value"`
	Protected bool   `json:"protected"`
}

type dumpInfo struct {
	Header map[string]any `json:"header"`
	TLVs   []dumpTLV      `json:"tlvs"`
}

func tlvValueString(t uint16, v []byte, le binary.ByteOrder) string {
	switch {
	case t == tlvSecCnt && len(v) == 4:
		return fmt.Sprintf("%d", le.Uint32(v))
	case t == tlvDependency && len(v) == 12:
		return fmt.Sprintf("image=%d version=%d.%d.%d+%d", v[0], v[4], v[5], le.Uint16(v[6:]), le.Uint32(v[8:]))
	}
	return hex.EncodeToString(v)
}

// DumpInfo prints header and TLV information of an image.
func DumpInfo(path, format string, w io.Writer) error {
	b, err := readImageFile(path)
	if err != nil {
		return err
	}
	if len(b) < imageHeaderSize {
		return errors.New("file too small to be an MCUboot image")
	}
	var le binary.ByteOrder = binary.LittleEndian
	if le.Uint32(b[0:]) != imageMagic {
		le = binary.BigEndian
		if le.Uint32(b[0:]) != imageMagic {
			return errors.New("invalid image magic; is this an MCUboot image?")
		}
	}
	hdrSize, protSize, imgSize := int(le.Uint16(b[8:])), int(le.Uint16(b[10:])), int(le.Uint32(b[12:]))
	flags := le.Uint32(b[16:])
	ver := Version{uint16(b[20]), uint16(b[21]), le.Uint16(b[22:]), le.Uint32(b[24:])}

	info := dumpInfo{Header: map[string]any{
		"magic": fmt.Sprintf("0x%x", imageMagic), "load_addr": fmt.Sprintf("0x%x", le.Uint32(b[4:])),
		"header_size": hdrSize, "protected_tlv_size": protSize, "image_size": imgSize,
		"image_flags": fmt.Sprintf("0x%x", flags), "image_version": ver.String(),
	}}
	off := hdrSize + imgSize
	for _, protected := range []bool{true, false} {
		if off+tlvInfoSize > len(b) {
			break
		}
		magic, tot := le.Uint16(b[off:]), int(le.Uint16(b[off+2:]))
		want := uint16(tlvInfoMagic)
		if protected {
			want = tlvProtInfoMagic
		}
		if magic != want || off+tot > len(b) {
			if protected {
				continue
			}
			break
		}
		for p := off + tlvInfoSize; p+tlvSize <= off+tot; {
			var t uint16
			if protected && !isPredefinedTLV(uint16(b[p])) {
				t = le.Uint16(b[p:])
			} else {
				t = uint16(b[p])
			}
			l := int(le.Uint16(b[p+2:]))
			if p+tlvSize+l > off+tot {
				break
			}
			name, ok := tlvNames[t]
			if !ok {
				name = "CUSTOM"
			}
			info.TLVs = append(info.TLVs, dumpTLV{name, fmt.Sprintf("0x%x", t), l,
				tlvValueString(t, b[p+tlvSize:p+tlvSize+l], le), protected})
			p += tlvSize + l
		}
		off += tot
	}

	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	fmt.Fprintf(w, "Image header:\n")
	for _, k := range []string{"magic", "load_addr", "header_size", "protected_tlv_size", "image_size", "image_flags", "image_version"} {
		fmt.Fprintf(w, "  %-20s %v\n", k+":", info.Header[k])
	}
	fmt.Fprintf(w, "TLVs:\n")
	for _, t := range info.TLVs {
		area := "tlv"
		if t.Protected {
			area = "protected"
		}
		fmt.Fprintf(w, "  [%s] %s (%s, len=%d): %s\n", area, t.Name, t.Type, t.Length, t.Value)
	}
	return nil
}
