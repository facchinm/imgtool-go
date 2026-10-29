package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Ordered key/value tree mirroring upstream's imginfo dict. Leaf values are
// int, string or []byte; inner nodes are omap or []any.
type kv struct {
	k string
	v any
}
type omap []kv

func (m omap) get(k string) (any, bool) {
	for _, e := range m {
		if e.k == k {
			return e.v, true
		}
	}
	return nil, false
}

func (m omap) int(k string) int { v, _ := m.get(k); i, _ := v.(int); return i }

var (
	bootMagic  = []byte{0x77, 0xc2, 0x95, 0xf3, 0x60, 0xd2, 0xef, 0x7f, 0x35, 0x52, 0x50, 0x0f, 0x2c, 0xb6, 0x79, 0x80}
	bootMagic2 = []byte{0x2d, 0xe1, 0x5d, 0x29, 0x41, 0x0b, 0x8d, 0x77, 0x67, 0x9c, 0x11, 0x0f, 0x1f, 0x8a}
)

var imageFlagNames = []struct {
	name string
	bit  int
}{
	{"PIC", 0x1}, {"ENCRYPTED_AES128", 0x4}, {"ENCRYPTED_AES256", 0x8}, {"NON_BOOTABLE", 0x10},
	{"RAM_LOAD", 0x20}, {"ROM_FIXED", 0x100}, {"COMPRESSED_LZMA1", 0x200},
	{"COMPRESSED_LZMA2", 0x400}, {"COMPRESSED_ARM_THUMB", 0x800},
}

var errTruncated = errors.New("image is truncated or malformed")

// readImgInfo parses an image like upstream's dumpinfo._read_imginfo. Warnings
// are written to warn.
func readImgInfo(path string, warn io.Writer) (omap, error) {
	b, err := readImageFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 28 {
		return nil, errTruncated
	}
	le := binary.LittleEndian
	header := omap{
		{"magic", int(le.Uint32(b[0:]))}, {"load_addr", int(le.Uint32(b[4:]))},
		{"hdr_size", int(le.Uint16(b[8:]))}, {"protected_tlv_size", int(le.Uint16(b[10:]))},
		{"img_size", int(le.Uint32(b[12:]))}, {"flags", int(le.Uint32(b[16:]))},
		{"version", fmt.Sprintf("%d.%d.%d+%d", b[20], b[21], le.Uint16(b[22:]), le.Uint32(b[24:]))},
	}

	readTLVs := func(off, end int) ([]any, error) {
		list := []any{}
		for off < end {
			if off+tlvSize > len(b) {
				return nil, errTruncated
			}
			t, l := int(le.Uint16(b[off:])), int(le.Uint16(b[off+2:]))
			off += tlvSize
			if off+l > len(b) {
				return nil, errTruncated
			}
			name, ok := tlvNames[uint16(t)]
			if !ok {
				name = "UNKNOWN"
			}
			list = append(list, omap{{"type", t}, {"type_name", name}, {"len", l}, {"data", b[off : off+l]}})
			off += l
		}
		return list, nil
	}

	off := header.int("hdr_size") + header.int("img_size")
	protHdr, prot := omap{}, []any{}
	if header.int("protected_tlv_size") != 0 {
		if off+tlvInfoSize > len(b) {
			return nil, errTruncated
		}
		tot := int(le.Uint16(b[off+2:]))
		protHdr = omap{{"magic", int(le.Uint16(b[off:]))}, {"tlv_tot", tot}}
		if prot, err = readTLVs(off+tlvInfoSize, off+tot); err != nil {
			return nil, err
		}
		off += tot
	}
	if off+tlvInfoSize > len(b) {
		return nil, errTruncated
	}
	tot := int(le.Uint16(b[off+2:]))
	tlvHdr := omap{{"magic", int(le.Uint16(b[off:]))}, {"tlv_tot", tot}}
	tlvs, err := readTLVs(off+tlvInfoSize, off+tot)
	if err != nil {
		return nil, err
	}
	tlvEnd := off + tot

	trailer := omap{}
	if len(b) > tlvEnd {
		if len(b) < len(bootMagic) {
			return nil, errTruncated
		}
		toff := len(b) - len(bootMagic)
		magic := b[toff:]
		trailer = append(trailer, kv{"magic", magic})
		maxAlign := 0
		switch {
		case bytes.Equal(magic, bootMagic):
			maxAlign = 8
		case bytes.Equal(magic[len(magic)-len(bootMagic2):], bootMagic2):
			maxAlign = int(le.Uint16(magic))
		default:
			fmt.Fprintln(warn, "Warning: the trailer magic value is invalid!")
		}
		if maxAlign != 0 {
			if maxAlign > len(bootMagic) {
				toff -= maxAlign - len(bootMagic)
			}
			for _, k := range []string{"image_ok", "copy_done", "swap_info"} {
				toff -= maxAlign
				if toff < 0 {
					return nil, errTruncated
				}
				trailer = append(trailer, kv{k, int(b[toff])})
			}
			toff -= maxAlign
			if toff < 0 {
				return nil, errTruncated
			}
			trailer = append(trailer, kv{"swap_size", int(le.Uint32(b[toff:]))})
			if header.int("flags")&(flagEncAES128|flagEncAES256) != 0 {
				trailer = append(trailer, kv{"key_field_len", alignUp(16, maxAlign) * 2})
			}
		}
	}

	return omap{
		{"filename", filepath.Base(path)},
		{"header", header},
		{"tlv_area", omap{{"tlv_hdr_prot", protHdr}, {"tlvs_prot", prot}, {"tlv_hdr", tlvHdr}, {"tlvs", tlvs}}},
		{"trailer", trailer},
	}, nil
}

// DumpInfo writes image information in the "human", "json" or "yaml" format.
// stdout selects upstream's trailing-newline behavior for JSON.
func DumpInfo(path, format string, w io.Writer, stdout bool) error {
	info, err := readImgInfo(path, os.Stdout)
	if err != nil {
		return err
	}
	switch format {
	case "human":
		writeHuman(info, w)
	case "json":
		var sb strings.Builder
		writeJSON(&sb, info, 0)
		if stdout {
			sb.WriteByte('\n')
		}
		_, err = io.WriteString(w, sb.String())
	case "yaml":
		var sb strings.Builder
		writeYAMLMap(&sb, info, 0, false)
		_, err = io.WriteString(w, sb.String())
	default:
		return fmt.Errorf("invalid output format: %s", format)
	}
	return err
}

const lineLength = 60

func humanRow(text string) string {
	text = "#### " + text + " "
	return text + strings.Repeat("#", max(lineLength-len(text), 0))
}

func humanFrame(headerText, content string) string {
	header := "#### " + headerText + " "
	lines := []string{header + strings.Repeat("#", max(lineLength-len(header), 0))}
	empty := "|" + strings.Repeat(" ", lineLength-2) + "|"
	pre := "|" + strings.Repeat(" ", max((lineLength-len(content))/2-1, 0))
	post := strings.Repeat(" ", max(lineLength-len(pre)-len(content)-1, 0)) + "|"
	lines = append(lines, empty, pre+content+post, empty, strings.Repeat("#", lineLength))
	return strings.Join(lines, "\n")
}

func humanTLVs(list []any) string {
	ind := strings.Repeat(" ", lineLength/8)
	var lines []string
	for _, it := range list {
		t := it.(omap)
		v, _ := t.get("type_name")
		d, _ := t.get("data")
		data := d.([]byte)
		lines = append(lines, ind+" "+strings.Repeat("-", 45),
			fmt.Sprintf("%s type: %s (%#x)", ind, v, t.int("type")),
			fmt.Sprintf("%s len:  %#x", ind, t.int("len")))
		line := ind + " data: "
		for j, c := range data {
			line += fmt.Sprintf("0x%02x ", c)
			if (j+1)%8 == 0 && j+1 != len(data) {
				lines = append(lines, line)
				line = strings.Repeat(" ", lineLength/8+7)
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func pyHex(v int) string { return "0x" + strconv.FormatInt(int64(v), 16) }

func parseStatus(v int) string {
	names := map[int]string{1: "SET", 2: "BAD", 3: "UNSET", 4: "ANY"}
	if n, ok := names[v]; ok {
		return fmt.Sprintf("%s (%s)", n, pyHex(v))
	}
	return fmt.Sprintf("INVALID (%s)", pyHex(v))
}

func writeHuman(info omap, w io.Writer) {
	p := func(s ...string) { fmt.Fprintln(w, strings.Join(s, " ")) }
	fn, _ := info.get("filename")
	h, _ := info.get("header")
	ta, _ := info.get("tlv_area")
	tr, _ := info.get("trailer")
	header, tlvArea, trailer := h.(omap), ta.(omap), tr.(omap)

	p("Printing content of signed image:", fn.(string), "\n")
	p(humanRow("Image header (offset: 0x0)"))
	for _, e := range header {
		var val string
		switch v := e.v.(type) {
		case string:
			val = v
		case int:
			val = pyHex(v)
			if e.k == "flags" && v != 0 {
				var parts []string
				for _, f := range imageFlagNames {
					if v&f.bit != 0 {
						parts = append(parts, fmt.Sprintf("%s (%s)", f.name, pyHex(f.bit)))
					}
				}
				val = strings.Join(parts, "\n"+strings.Repeat(" ", 20))
			}
		}
		fmt.Fprintf(w, "%s:%s%s\n", e.k, strings.Repeat(" ", max(19-len(e.k), 0)), val)
	}
	p(strings.Repeat("#", lineLength))

	off := header.int("hdr_size")
	p(humanFrame("Payload (offset: "+pyHex(off)+")", "FW image (size: "+pyHex(header.int("img_size"))+" Bytes)"))
	off += header.int("img_size")
	area := func(name, hdrKey, listKey string) {
		hv, _ := tlvArea.get(hdrKey)
		lv, _ := tlvArea.get(listKey)
		hdr := hv.(omap)
		p(humanRow(name + " (offset: " + pyHex(off) + ")"))
		p("magic:    ", pyHex(hdr.int("magic")))
		p("area size:", pyHex(hdr.int("tlv_tot")))
		p(humanTLVs(lv.([]any)))
		p(strings.Repeat("#", lineLength))
	}
	if header.int("protected_tlv_size") != 0 {
		area("Protected TLV area", "tlv_hdr_prot", "tlvs_prot")
	}
	off += header.int("protected_tlv_size")
	area("TLV area", "tlv_hdr", "tlvs")

	if mv, ok := trailer.get("magic"); ok && len(mv.([]byte)) > 0 {
		magic := mv.([]byte)
		p(humanRow("Image trailer (offset: unknown)"))
		notice := "(Note: some fields may not be used, depending on the update strategy)\n"
		var chunks []string
		for i := 0; i < len(notice); i += lineLength {
			chunks = append(chunks, notice[i:min(i+lineLength, len(notice))])
		}
		p(strings.Join(chunks, "\n"))
		p("swap status: (len: unknown)")
		if v, ok := trailer.get("key_field_len"); ok {
			p("enc. keys:  ", fmt.Sprintf("(len: %s, if BOOT_SWAP_SAVE_ENCTLV is unset)", pyHex(v.(int))))
		} else {
			p("enc. keys:  ", "Image not encrypted")
		}
		if _, ok := trailer.get("swap_size"); ok {
			v := trailer.int("swap_size")
			if v == 0xffffffff {
				p("swap size:  ", "unknown")
			} else {
				p("swap size:  ", pyHex(v)+" octal: "+strconv.Itoa(v))
			}
		}
		for _, k := range []string{"swap_info", "copy_done", "image_ok"} {
			if _, ok := trailer.get(k); ok {
				p(k+":"+strings.Repeat(" ", 11-len(k)), parseStatus(trailer.int(k)))
			}
		}
		var m strings.Builder
		for i := range len(bootMagic) {
			if i < len(magic) {
				fmt.Fprintf(&m, "0x%02x ", magic[i])
			}
			if i == len(bootMagic)/2-1 {
				m.WriteString("\n" + strings.Repeat(" ", 13))
			}
		}
		p("boot magic: ", m.String())
		p()
	}
	p(humanRow("End of Image "))
}

// writeJSON mirrors Python's json.dump(indent=2) with bytes rendered as hex.
func writeJSON(sb *strings.Builder, v any, ind int) {
	pad := func(n int) string { return strings.Repeat("  ", n) }
	switch x := v.(type) {
	case omap:
		if len(x) == 0 {
			sb.WriteString("{}")
			return
		}
		sb.WriteString("{")
		for i, e := range x {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("\n" + pad(ind+1) + pyJSONString(e.k) + ": ")
			writeJSON(sb, e.v, ind+1)
		}
		sb.WriteString("\n" + pad(ind) + "}")
	case []any:
		if len(x) == 0 {
			sb.WriteString("[]")
			return
		}
		sb.WriteString("[")
		for i, e := range x {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("\n" + pad(ind+1))
			writeJSON(sb, e, ind+1)
		}
		sb.WriteString("\n" + pad(ind) + "]")
	case int:
		sb.WriteString(strconv.Itoa(x))
	case string:
		sb.WriteString(pyJSONString(x))
	case []byte:
		sb.WriteString(fmt.Sprintf("%q", fmt.Sprintf("%x", x)))
	}
}

// pyJSONString quotes s like Python's json module (ensure_ascii=True).
func pyJSONString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r > 0x7f && r < 0x10000):
				fmt.Fprintf(&sb, `\u%04x`, r)
			case r >= 0x10000:
				r -= 0x10000
				fmt.Fprintf(&sb, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// writeYAMLMap mirrors PyYAML's yaml.dump(sort_keys=False) block style.
// The first key is not indented when inline follows a "- " sequence marker.
func writeYAMLMap(sb *strings.Builder, m omap, ind int, inline bool) {
	for i, e := range m {
		if i > 0 || !inline {
			sb.WriteString(strings.Repeat(" ", ind))
		}
		sb.WriteString(yamlScalarString(e.k) + ":")
		writeYAMLValue(sb, e.v, ind)
	}
}

func writeYAMLValue(sb *strings.Builder, v any, ind int) {
	switch x := v.(type) {
	case omap:
		if len(x) == 0 {
			sb.WriteString(" {}\n")
			return
		}
		sb.WriteString("\n")
		writeYAMLMap(sb, x, ind+2, false)
	case []any:
		if len(x) == 0 {
			sb.WriteString(" []\n")
			return
		}
		sb.WriteString("\n")
		for _, it := range x {
			sb.WriteString(strings.Repeat(" ", ind) + "- ")
			writeYAMLMap(sb, it.(omap), ind+2, true)
		}
	case int:
		sb.WriteString(" " + strconv.Itoa(x) + "\n")
	case string:
		sb.WriteString(" " + yamlScalarString(x) + "\n")
	case []byte:
		enc := base64.StdEncoding.EncodeToString(x)
		if enc == "" {
			sb.WriteString(" !!binary \"\"\n")
			return
		}
		sb.WriteString(" !!binary |\n")
		for len(enc) > 0 {
			n := min(76, len(enc))
			sb.WriteString(strings.Repeat(" ", ind+2) + enc[:n] + "\n")
			enc = enc[n:]
		}
	}
}

// YAML 1.1 implicit resolvers (as used by PyYAML) that would turn a plain
// scalar into a non-string.
var yamlImplicit = regexp.MustCompile(`^(?:` +
	`yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF` +
	`|~|null|Null|NULL` +
	`|[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+` +
	`|[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|[-+]?(?:[0-9][0-9_]*)(?:[eE][-+][0-9]+)|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?` +
	`|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)` +
	`|[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]` +
	`|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?` +
	`|<<|=)$`)

func yamlScalarString(s string) string {
	printable := true
	for _, r := range s {
		if r > 0x7e || (r < 0x20 && r != '\n') || r == utf8.RuneError {
			printable = false
			break
		}
	}
	if !printable || strings.Contains(s, "\n") {
		var sb strings.Builder
		sb.WriteByte('"')
		for _, r := range s {
			switch {
			case r == '"' || r == '\\':
				sb.WriteString(`\` + string(r))
			case r == '\n':
				sb.WriteString(`\n`)
			case r == '\t':
				sb.WriteString(`\t`)
			case r >= 0x20 && r <= 0x7e:
				sb.WriteRune(r)
			case r < 0x100:
				fmt.Fprintf(&sb, `\x%02X`, r)
			case r < 0x10000:
				fmt.Fprintf(&sb, `\u%04X`, r)
			default:
				fmt.Fprintf(&sb, `\U%08X`, r)
			}
		}
		sb.WriteByte('"')
		return sb.String()
	}
	plain := s != "" && !yamlImplicit.MatchString(s) &&
		s[0] != ' ' && s[len(s)-1] != ' ' &&
		!strings.ContainsAny(s[:1], ",[]{}#&*!|>'\"%@`") &&
		!(strings.ContainsAny(s[:1], "-?:") && (len(s) == 1 || s[1] == ' ')) &&
		!strings.Contains(s, ": ") && !strings.Contains(s, " #") && !strings.HasSuffix(s, ":")
	if plain {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
