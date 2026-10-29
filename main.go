package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const imgtoolVersion = "2.4.0-go"

type usageError string

func (u usageError) Error() string { return string(u) }

func usagef(f string, a ...any) error { return usageError(fmt.Sprintf(f, a...)) }

const usageText = `Usage: imgtool [-h] <command> [options]

Commands:
  create       alias of sign
  dumpinfo     Print header and TLV area information of a signed image
  getpub       Dump public key from keypair
  getpriv      Dump private key from keypair
  getpubhash   Dump the SHA256 hash of the public key
  keygen       Generate pub/private keypair
  keyinfo      Print whether a key is private or public
  sign         Create a signed or unsigned image
  verify       Check that signed image can be verified by given key
  version      Print imgtool version information
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usageText)
		return
	}
	cmds := map[string]func([]string) error{
		"keygen": cmdKeygen, "getpub": cmdGetpub, "getpubhash": cmdGetpubhash,
		"keyinfo": cmdKeyinfo, "getpriv": cmdGetpriv, "verify": cmdVerify, "sign": cmdSign, "create": cmdSign,
		"dumpinfo": cmdDumpinfo, "version": func([]string) error { fmt.Println(imgtoolVersion); return nil },
	}
	fn, ok := cmds[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: no such command %q.\n\n%s", args[0], usageText)
		os.Exit(2)
	}
	if err := fn(args[1:]); err != nil {
		if _, isUsage := err.(usageError); isUsage {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newFlags returns a FlagSet that reports errors instead of exiting.
func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("imgtool "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseInterspersed parses flags that may appear before or after positional args.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if err == flag.ErrHelp {
				fs.SetOutput(os.Stderr)
				fs.PrintDefaults()
				os.Exit(0)
			}
			return nil, usageError(err.Error())
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func str(fs *flag.FlagSet, def string, names ...string) *string {
	p := new(string)
	*p = def
	for _, n := range names {
		fs.StringVar(p, n, def, "")
	}
	return p
}

func boolean(fs *flag.FlagSet, names ...string) *bool {
	p := new(bool)
	for _, n := range names {
		fs.BoolVar(p, n, false, "")
	}
	return p
}

func logf(f string, a ...any) { fmt.Printf(f, a...) }

func writeOut(path, content string) error {
	if path == "" {
		_, err := io.WriteString(os.Stdout, content)
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func cmdKeygen(args []string) error {
	fs := newFlags("keygen")
	typ := str(fs, "", "t", "type")
	keyfile := str(fs, "", "k", "key")
	pw := boolean(fs, "p", "password")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *typ == "" || *keyfile == "" {
		return usagef("keygen requires -t/--type (one of: %s) and -k/--key", strings.Join(keyTypes, ", "))
	}
	if *pw {
		return usagef("password-protected keys are not supported")
	}
	k, err := GenerateKey(*typ)
	if err != nil {
		return usagef("%v", err)
	}
	pemBytes, err := k.PrivatePEM()
	if err != nil {
		return err
	}
	return os.WriteFile(*keyfile, pemBytes, 0o600)
}

var suffixRe = regexp.MustCompile(`^[A-Za-z0-9_]*$`)

func cmdGetpub(args []string) error {
	fs := newFlags("getpub")
	lang := str(fs, "", "l", "lang")
	enc := str(fs, "", "e", "encoding")
	suffix := str(fs, "", "name-suffix")
	keyfile := str(fs, "", "k", "key")
	out := str(fs, "", "o", "output")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *keyfile == "" {
		return usagef("getpub requires -k/--key")
	}
	if *enc != "" && *lang != "" {
		return usagef("Please use only one of `--encoding/-e` or `--lang/-l`")
	}
	if *enc == "" {
		switch *lang {
		case "", "c":
			*enc = "lang-c"
		case "rust":
			*enc = "lang-rust"
		default:
			return usagef("invalid lang %q (valid: c, rust)", *lang)
		}
	}
	if !suffixRe.MatchString(*suffix) {
		return usagef("%q must contain only [A-Za-z0-9_]", *suffix)
	}
	if *suffix != "" && (*enc == "pem" || *enc == "raw") {
		return usagef("`--name-suffix` is only meaningful for lang-c / lang-rust encodings")
	}
	k, err := LoadKey(*keyfile)
	if err != nil {
		return err
	}
	switch *enc {
	case "lang-c":
		return writeOut(*out, k.EmitCPublic(*suffix))
	case "lang-rust":
		return writeOut(*out, k.EmitRustPublic(*suffix))
	case "pem":
		return writeOut(*out, string(k.PublicPEM()))
	case "raw":
		return writeOut(*out, string(k.PublicBytes()))
	}
	return usagef("invalid encoding %q (valid: lang-c, lang-rust, pem, raw)", *enc)
}

func cmdGetpubhash(args []string) error {
	fs := newFlags("getpubhash")
	enc := str(fs, "lang-c", "e", "encoding")
	suffix := str(fs, "", "name-suffix")
	keyfile := str(fs, "", "k", "key")
	out := str(fs, "", "o", "output")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *keyfile == "" {
		return usagef("getpubhash requires -k/--key")
	}
	if !suffixRe.MatchString(*suffix) {
		return usagef("%q must contain only [A-Za-z0-9_]", *suffix)
	}
	k, err := LoadKey(*keyfile)
	if err != nil {
		return err
	}
	switch *enc {
	case "lang-c":
		return writeOut(*out, k.EmitCPublicHash(*suffix))
	case "raw":
		return writeOut(*out, string(digestOf("256", k.PublicBytes())))
	}
	return usagef("invalid encoding %q (valid: lang-c, raw)", *enc)
}

func cmdKeyinfo(args []string) error {
	fs := newFlags("keyinfo")
	keyfile := str(fs, "", "k", "key")
	require := str(fs, "", "require")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *keyfile == "" {
		return usagef("keyinfo requires -k/--key")
	}
	k, err := LoadKey(*keyfile)
	if err != nil {
		return err
	}
	kind := "public"
	if k.HasPrivate() {
		kind = "private"
	}
	fmt.Println(kind)
	if *require != "" && *require != kind {
		return usagef("Key %s is %s, but %s was required.", *keyfile, kind, *require)
	}
	return nil
}

func cmdVerify(args []string) error {
	fs := newFlags("verify")
	keyfile := str(fs, "", "k", "key")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("verify requires exactly one IMGFILE")
	}
	var key *Key
	if *keyfile != "" {
		if key, err = LoadKey(*keyfile); err != nil {
			return err
		}
	}
	res, ver, digest, sig, err := VerifyImage(pos[0], key)
	if err != nil {
		return err
	}
	switch res {
	case VerifyOK:
		fmt.Println("Image was correctly validated")
		fmt.Printf("Image version: %d.%d.%d+%d\n", ver.Major, ver.Minor, ver.Revision, ver.Build)
		if digest != nil {
			fmt.Printf("Image digest: %x\n", digest)
		}
		if sig != nil && digest == nil {
			fmt.Printf("Image signature over image: %x\n", sig)
		}
		return nil
	case VerifyInvalidMagic:
		fmt.Println("Invalid image magic; is this an MCUboot image?")
	case VerifyInvalidTLVInfoMagic:
		fmt.Println("Invalid TLV info magic; is this an MCUboot image?")
	case VerifyInvalidHash:
		fmt.Println("Image has an invalid hash")
	case VerifyInvalidSignature:
		fmt.Println("No signature found for the given key")
	case VerifyKeyMismatch:
		fmt.Println("Key type does not match TLV record")
	}
	os.Exit(1)
	return nil
}

func cmdDumpinfo(args []string) error {
	fs := newFlags("dumpinfo")
	outfile := str(fs, "", "o", "outfile")
	format := str(fs, "", "f", "format")
	silent := boolean(fs, "s", "silent")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("dumpinfo requires exactly one IMGFILE")
	}
	if *format == "" {
		*format = "human"
	}
	if *format != "human" && *format != "json" {
		return usagef("unsupported format %q (human, json)", *format)
	}
	if !*silent {
		if err := DumpInfo(pos[0], *format, os.Stdout); err != nil {
			return err
		}
	}
	if *outfile != "" {
		f, err := os.Create(*outfile)
		if err != nil {
			return err
		}
		defer f.Close()
		return DumpInfo(pos[0], *format, f)
	}
	return nil
}

// multiTLV collects repeated two-argument options (--custom-tlv TAG VALUE).
type multiTLV struct{ items [][2]string }

func (m *multiTLV) String() string { return "" }
func (m *multiTLV) Set(s string) error {
	i := strings.Index(s, "\x00")
	m.items = append(m.items, [2]string{s[:i], s[i+1:]})
	return nil
}

// joinTwoArgOpts rewrites "--opt A B" into "--opt=A\x00B" for the given options.
func joinTwoArgOpts(args []string, opts ...string) ([]string, error) {
	var out []string
	for i := 0; i < len(args); i++ {
		matched := false
		if strings.HasPrefix(args[i], "-") {
			name := strings.TrimLeft(args[i], "-")
			for _, o := range opts {
				if name != o {
					continue
				}
				if i+2 >= len(args) {
					return nil, usagef("option --%s requires 2 arguments", o)
				}
				out = append(out, "--"+o+"="+args[i+1]+"\x00"+args[i+2])
				i += 2
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, args[i])
		}
	}
	return out, nil
}

func cmdSign(args []string) error {
	fs := newFlags("sign")
	args, err := joinTwoArgOpts(args, "custom-tlv", "custom-tlv-file")
	if err != nil {
		return err
	}
	var customTLV, customTLVFile multiTLV
	fs.Var(&customTLV, "custom-tlv", "")
	fs.Var(&customTLVFile, "custom-tlv-file", "")

	nonBootable := boolean(fs, "non-bootable")
	erased := str(fs, "", "R", "erased-val")
	endian := str(fs, "little", "e", "endian")
	overwriteOnly := boolean(fs, "overwrite-only")
	confirm := boolean(fs, "confirm")
	test := boolean(fs, "test")
	pad := boolean(fs, "pad")
	padHeader := boolean(fs, "pad-header")
	padSig := boolean(fs, "pad-sig")
	pure := boolean(fs, "pure")
	maxSectors := str(fs, "", "M", "max-sectors")
	slotSize := str(fs, "", "S", "slot-size")
	hdrSize := str(fs, "", "H", "header-size")
	hexAddr := str(fs, "", "x", "hex-addr")
	loadAddr := str(fs, "", "L", "load-addr")
	romFixed := str(fs, "", "F", "rom-fixed")
	deps := str(fs, "", "d", "dependencies")
	secCnt := str(fs, "", "s", "security-counter")
	version := str(fs, "", "v", "version")
	align := str(fs, "1", "align")
	maxAlign := str(fs, "", "max-align")
	pkFormat := str(fs, "hash", "public-key-format")
	keyfile := str(fs, "", "k", "key")
	fixSig := str(fs, "", "fix-sig")
	fixSigPub := str(fs, "", "fix-sig-pubkey")
	sigOut := str(fs, "", "sig-out")
	userSHA := str(fs, "auto", "sha")
	vector := str(fs, "", "vector-to-sign")
	vid := str(fs, "", "vid")
	cid := str(fs, "", "cid")
	encrypt := str(fs, "", "E", "encrypt")
	encKeyLen := str(fs, "128", "encrypt-keylen")
	clear := boolean(fs, "c", "clear")
	saveEncTLV := boolean(fs, "save-enctlv")
	hmacSHA := str(fs, "auto", "hmac-sha")
	compression := str(fs, "disabled", "compression")
	for _, unsupported := range []string{"boot-record"} {
		fs.Var(unsupportedFlag(unsupported), unsupported, "")
	}

	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usagef("sign requires INFILE and OUTFILE")
	}
	infile, outfile := pos[0], pos[1]

	parseNum := func(name, s string) (uint64, error) {
		n, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return 0, usagef("%s: %q is not a valid integer; use 0x/0o/0b prefixes as needed", name, s)
		}
		return n, nil
	}
	for name, v := range map[string]*string{"--slot-size": slotSize, "--header-size": hdrSize, "--version": version} {
		if *v == "" {
			return usagef("missing required option %s", name)
		}
	}
	ss, err := parseNum("--slot-size", *slotSize)
	if err != nil {
		return err
	}
	hs, err := parseNum("--header-size", *hdrSize)
	if err != nil {
		return err
	}
	if hs < imageHeaderSize {
		return usagef("Minimum value for -H/--header-size is %d", imageHeaderSize)
	}
	ver, err := DecodeVersion(*version)
	if err != nil {
		return usagef("%v", err)
	}

	opt := func(name, s string) (uint32, bool, error) {
		if s == "" {
			return 0, false, nil
		}
		n, err := parseNum(name, s)
		return uint32(n), true, err
	}
	la, _, err := opt("--load-addr", *loadAddr)
	if err != nil {
		return err
	}
	rf, _, err := opt("--rom-fixed", *romFixed)
	if err != nil {
		return err
	}
	ha, haSet, err := opt("--hex-addr", *hexAddr)
	if err != nil {
		return err
	}
	var ms uint64
	if *maxSectors != "" {
		if ms, err = parseNum("--max-sectors", *maxSectors); err != nil {
			return err
		}
	}
	al, err := parseNum("--align", *align)
	if err != nil {
		return err
	}
	var ma uint64
	if *maxAlign != "" {
		if ma, err = parseNum("--max-align", *maxAlign); err != nil {
			return err
		}
		switch ma {
		case 8, 16, 32, 64, 128:
		default:
			return usagef("--max-align must be one of 8, 16, 32, 64, 128")
		}
	}
	switch al {
	case 1, 2, 4, 8, 16, 32, 64, 128:
	default:
		return usagef("--align must be one of 1, 2, 4, 8, 16, 32, 64, 128")
	}
	var erasedVal byte = 0xff
	switch *erased {
	case "", "0xff":
	case "0":
		erasedVal = 0
	default:
		return usagef("--erased-val must be 0 or 0xff")
	}
	var order binary.ByteOrder
	switch *endian {
	case "little":
		order = binary.LittleEndian
	case "big":
		order = binary.BigEndian
	default:
		return usagef("--endian must be little or big")
	}
	switch *pkFormat {
	case "hash", "full":
	default:
		return usagef("--public-key-format must be hash or full")
	}
	switch *userSHA {
	case "auto", "256", "384", "512":
	default:
		return usagef("--sha must be one of auto, 256, 384, 512")
	}
	if *vector != "" && *vector != "payload" && *vector != "digest" {
		return usagef("--vector-to-sign must be payload or digest")
	}
	if *pure && *userSHA != "auto" {
		return usagef("Pure signatures, currently, enforces preferred hash algorithm, and forbids sha selection by user.")
	}
	if *confirm || *test {
		*pad = true
	}

	var secCntVal *uint32
	switch strings.ToLower(*secCnt) {
	case "":
	case "auto":
		v := uint32(ver.Major)<<24 + uint32(ver.Minor)<<16 + uint32(ver.Revision)
		secCntVal = &v
	default:
		n, err := strconv.ParseUint(*secCnt, 0, 32)
		if err != nil {
			return usagef("%s is not a valid integer for --security-counter", *secCnt)
		}
		v := uint32(n)
		secCntVal = &v
	}
	newImg := func() (*Image, error) {
		im, err := NewImage(&Image{
			Version: ver, HeaderSize: int(hs), PadHeader: *padHeader, Pad: *pad, Confirm: *confirm,
			Test: *test, Align: int(al), SlotSize: int(ss), MaxSectors: int(ms),
			OverwriteOnly: *overwriteOnly, Order: order, LoadAddr: la, ROMFixed: rf,
			ErasedVal: erasedVal, MaxAlign: int(ma), SaveEncTLV: *saveEncTLV, NonBootable: *nonBootable,
			VID: *vid, CID: *cid, SecurityCnt: secCntVal,
		})
		if err != nil {
			return nil, usagef("%v", err)
		}
		return im, nil
	}
	switch *compression {
	case "disabled", "lzma2", "lzma2armthumb":
	default:
		return usagef("--compression must be one of disabled, lzma2, lzma2armthumb")
	}

	co := CreateOpts{PubKeyFormat: *pkFormat, UserSHA: *userSHA, Pure: *pure, PadSig: *padSig, Vector: *vector}
	if *encKeyLen != "128" && *encKeyLen != "256" {
		return usagef("--encrypt-keylen must be 128 or 256")
	}
	if *hmacSHA != "auto" && *hmacSHA != "256" && *hmacSHA != "512" {
		return usagef("--hmac-sha must be one of auto, 256, 512")
	}
	co.EncKeyLen, _ = strconv.Atoi(*encKeyLen)
	co.Clear, co.HMACSHA = *clear, *hmacSHA
	if *encrypt != "" {
		if co.EncKey, err = LoadKey(*encrypt); err != nil {
			return err
		}
	}
	if *keyfile != "" {
		if co.Key, err = LoadKey(*keyfile); err != nil {
			return err
		}
		if !co.Key.CanSign() {
			return usagef("Cannot sign with a public-only PEM; signing requires the private key.")
		}
	}
	if *deps != "" {
		if co.Deps, err = ParseDependencies(*deps); err != nil {
			return usagef("%v", err)
		}
	}
	seen := map[uint16]bool{}
	addCustom := func(tag, val string, isFile bool) error {
		t, err := strconv.ParseUint(tag, 0, 32)
		if err != nil {
			return usagef("invalid custom TLV tag %q", tag)
		}
		if t < tlvVendorResMin || t > tlvVendorResMax {
			return usagef("Invalid custom TLV type value '0x%04x', allowed value should be between 0x%04x and 0x%04x",
				t, tlvVendorResMin, tlvVendorResMax)
		}
		if seen[uint16(t)] {
			return usagef("Custom TLV %#x already exists.", t)
		}
		seen[uint16(t)] = true
		var data []byte
		switch {
		case isFile:
			if data, err = os.ReadFile(val); err != nil {
				return err
			}
		case strings.HasPrefix(val, "0x"):
			if len(val[2:])%2 != 0 {
				return usagef("Custom TLV length is odd.")
			}
			if data, err = hex.DecodeString(val[2:]); err != nil {
				return usagef("invalid custom TLV hex value: %v", err)
			}
		default:
			data = []byte(val)
		}
		co.Custom = append(co.Custom, CustomTLV{uint16(t), data})
		return nil
	}
	for _, it := range customTLV.items {
		if err := addCustom(it[0], it[1], false); err != nil {
			return err
		}
	}
	for _, it := range customTLVFile.items {
		if err := addCustom(it[0], it[1], true); err != nil {
			return err
		}
	}
	if *fixSig != "" {
		raw, err := os.ReadFile(*fixSig)
		if err != nil {
			return err
		}
		if co.FixedSig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err != nil {
			return usagef("invalid base64 in %s: %v", *fixSig, err)
		}
		if *fixSigPub == "" {
			return usagef("public key of the fixed signature is not specified")
		}
		if co.PubKey, err = LoadKey(*fixSigPub); err != nil {
			return err
		}
	}

	var im *Image
	if *compression != "disabled" {
		if im, err = BuildCompressed(newImg, infile, *compression, co); err != nil {
			return usagef("%v", err)
		}
	}
	if im == nil { // no compression requested, or it did not shrink the image
		if im, err = newImg(); err != nil {
			return err
		}
		if err := im.Load(infile); err != nil {
			return usagef("%v", err)
		}
		if err := im.Create(co); err != nil {
			return usagef("%v", err)
		}
	}
	var hexp *uint32
	if haSet {
		hexp = &ha
	}
	if err := im.Save(outfile, hexp); err != nil {
		return usagef("%v", err)
	}
	if *sigOut != "" {
		return os.WriteFile(*sigOut, []byte(base64.StdEncoding.EncodeToString(im.Signature)), 0o644)
	}
	return nil
}

type unsupportedFlag string

func (u unsupportedFlag) String() string { return "" }
func (u unsupportedFlag) Set(string) error {
	return usagef("option --%s is not supported by this Go implementation", string(u))
}

func cmdGetpriv(args []string) error {
	fs := newFlags("getpriv")
	keyfile := str(fs, "", "k", "key")
	format := str(fs, "", "f", "format")
	minimal := boolean(fs, "minimal")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *keyfile == "" {
		return usagef("getpriv requires -k/--key")
	}
	if *format != "" && *format != "openssl" && *format != "pkcs8" {
		return usagef("invalid format %q (valid: openssl, pkcs8)", *format)
	}
	k, err := LoadKey(*keyfile)
	if err != nil {
		return err
	}
	if !k.HasPrivate() {
		return usagef("operation get_private_bytes requires private key")
	}
	der, err := k.PrivateBytes(*minimal, *format)
	if err != nil {
		return usagef("%v", err)
	}
	return writeOut("", emitBytes("const unsigned char enc_priv_key[] = {", "};", der,
		"const unsigned int enc_priv_key_len = %d;"))
}
