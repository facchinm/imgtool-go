package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	imageMagic        = 0x96f3b83d
	imageHeaderSize   = 32
	defaultMaxSectors = 128
	defaultMaxAlign   = 8

	tlvInfoSize      = 4
	tlvSize          = 4
	tlvInfoMagic     = 0x6907
	tlvProtInfoMagic = 0x6908
	tlvVendorResMin  = 0x00a0
	tlvVendorResMax  = 0xfffe
)

const (
	flagPIC         = 0x01
	flagNonBootable = 0x10
	flagRAMLoad     = 0x20
	flagROMFixed    = 0x100
)

const (
	tlvKeyHash     = 0x01
	tlvPubKey      = 0x02
	tlvSHA256      = 0x10
	tlvSHA384      = 0x11
	tlvSHA512      = 0x12
	tlvRSA2048     = 0x20
	tlvECDSASIG    = 0x22
	tlvRSA3072     = 0x23
	tlvED25519     = 0x24
	tlvSigPure     = 0x25
	tlvDependency  = 0x40
	tlvSecCnt      = 0x50
	tlvBootRecord  = 0x60
	tlvDecompSize  = 0x70
	tlvDecompSHA   = 0x71
	tlvDecompSig   = 0x72
	tlvCompDecSize = 0x73
	tlvUUIDVID     = 0x74
	tlvUUIDCID     = 0x75
)

var tlvNames = map[uint16]string{
	tlvKeyHash: "KEYHASH", tlvPubKey: "PUBKEY", tlvSHA256: "SHA256", tlvSHA384: "SHA384",
	tlvSHA512: "SHA512", tlvRSA2048: "RSA2048", tlvECDSASIG: "ECDSASIG", tlvRSA3072: "RSA3072",
	tlvED25519: "ED25519", tlvSigPure: "SIG_PURE", 0x30: "ENCRSA2048", 0x31: "ENCKW",
	0x32: "ENCEC256", 0x33: "ENCX25519", 0x34: "ENCX25519_SHA512", tlvDependency: "DEPENDENCY",
	tlvSecCnt: "SEC_CNT", tlvBootRecord: "BOOT_RECORD", tlvDecompSize: "DECOMP_SIZE",
	tlvDecompSHA: "DECOMP_SHA", tlvDecompSig: "DECOMP_SIGNATURE", tlvCompDecSize: "COMP_DEC_SIZE",
	tlvUUIDVID: "UUID_VID", tlvUUIDCID: "UUID_CID",
}

func isPredefinedTLV(tag uint16) bool { _, ok := tlvNames[tag]; return ok }

// Version is a "major.minor.revision+build" image version.
type Version struct {
	Major, Minor, Revision uint16
	Build                  uint32
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d+%d", v.Major, v.Minor, v.Revision, v.Build)
}

var versionRe = regexp.MustCompile(`^([1-9]\d*|0)(\.([1-9]\d*|0)(\.([1-9]\d*|0)(\+([1-9]\d*|0))?)?)?$`)

func DecodeVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, errors.New("invalid version number, should be maj.min.rev+build with later parts optional")
	}
	n := func(i int) uint64 { v, _ := strconv.ParseUint(m[i], 10, 32); return v }
	v := Version{Major: uint16(n(1)), Minor: uint16(n(3)), Revision: uint16(n(5)), Build: uint32(n(7))}
	if n(1) > 255 || n(3) > 255 || n(5) > 0xffff {
		return v, errors.New("version component out of range")
	}
	return v, nil
}

type Dependency struct {
	ID      uint8
	Version Version
}

var (
	depImgRe = regexp.MustCompile(`\((\d+)`)
	depVerRe = regexp.MustCompile(`,\s*([0-9.+]+)\)`)
)

// ParseDependencies parses "(<image_ID>,<version>), ...".
func ParseDependencies(s string) ([]Dependency, error) {
	imgs := depImgRe.FindAllStringSubmatch(s, -1)
	vers := depVerRe.FindAllStringSubmatch(s, -1)
	if len(imgs) == 0 {
		return nil, fmt.Errorf("image dependency format is invalid: %s", s)
	}
	if len(imgs) != len(vers) {
		return nil, fmt.Errorf("mismatch between the number of dependency images and versions in: %s", s)
	}
	var deps []Dependency
	for i := range imgs {
		id, err := strconv.ParseUint(imgs[i][1], 10, 8)
		if err != nil {
			return nil, err
		}
		v, err := DecodeVersion(vers[i][1])
		if err != nil {
			return nil, err
		}
		deps = append(deps, Dependency{uint8(id), v})
	}
	return deps, nil
}

type tlvEntry struct {
	kind    uint16
	custom  bool // custom TLVs encode the type as a full 16-bit field
	payload []byte
}

type TLVArea struct {
	magic   uint16
	entries []tlvEntry
	order   binary.ByteOrder
}

func (t *TLVArea) Add(kind uint8, payload []byte) {
	t.entries = append(t.entries, tlvEntry{kind: uint16(kind), payload: payload})
}

func (t *TLVArea) AddCustom(kind uint16, payload []byte) {
	t.entries = append(t.entries, tlvEntry{kind: kind, custom: true, payload: payload})
}

func (t *TLVArea) size() int {
	if len(t.entries) == 0 {
		return 0
	}
	n := tlvInfoSize
	for _, e := range t.entries {
		n += tlvSize + len(e.payload)
	}
	return n
}

func (t *TLVArea) Bytes() []byte {
	if len(t.entries) == 0 {
		return nil
	}
	out := make([]byte, 4)
	t.order.PutUint16(out[0:], t.magic)
	t.order.PutUint16(out[2:], uint16(t.size()))
	for _, e := range t.entries {
		h := make([]byte, 4)
		if e.custom {
			t.order.PutUint16(h[0:], e.kind)
		} else {
			h[0], h[1] = byte(e.kind), 0
		}
		t.order.PutUint16(h[2:], uint16(len(e.payload)))
		out = append(out, h...)
		out = append(out, e.payload...)
	}
	return out
}

type CustomTLV struct {
	Tag   uint16
	Value []byte
}

func alignUp(n, a int) int { return (n + a - 1) &^ (a - 1) }

// Image holds an image being built.
type Image struct {
	Version       Version
	HeaderSize    int
	PadHeader     bool
	Pad           bool
	Confirm       bool
	Test          bool
	Align         int
	SlotSize      int
	MaxSectors    int
	OverwriteOnly bool
	Order         binary.ByteOrder
	LoadAddr      uint32
	ROMFixed      uint32
	ErasedVal     byte
	SecurityCnt   *uint32
	MaxAlign      int
	NonBootable   bool
	SaveEncTLV    bool
	EncKey        *Key
	enctlvLen     int
	InFileData    []byte
	ImageHash     []byte
	VID, CID      string
	BaseAddr      *uint32
	Payload       []byte
	ImageSize     int
	Signature     []byte
	bootMagic     []byte
}

func NewImage(o *Image) (*Image, error) {
	if o.LoadAddr != 0 && o.ROMFixed != 0 {
		return nil, errors.New("can not set rom-fixed and load-addr at the same time")
	}
	if o.MaxAlign == 0 {
		o.MaxAlign = defaultMaxAlign
		if o.Align > o.MaxAlign {
			o.MaxAlign = o.Align
		}
	}
	if o.MaxSectors == 0 {
		o.MaxSectors = defaultMaxSectors
	}
	if o.Order == nil {
		o.Order = binary.LittleEndian
	}
	if o.MaxAlign == defaultMaxAlign {
		o.bootMagic = []byte{0x77, 0xc2, 0x95, 0xf3, 0x60, 0xd2, 0xef, 0x7f,
			0x35, 0x52, 0x50, 0x0f, 0x2c, 0xb6, 0x79, 0x80}
	} else {
		lsb, msb := byte(o.MaxAlign&0xff), byte((o.MaxAlign&0xff00)>>8)
		al := []byte{lsb, msb}
		if o.Order == binary.BigEndian {
			al = []byte{msb, lsb}
		}
		o.bootMagic = append(al, 0x2d, 0xe1, 0x5d, 0x29, 0x41, 0x0b, 0x8d, 0x77,
			0x67, 0x9c, 0x11, 0x0f, 0x1f, 0x8a)
	}
	return o, nil
}

// Load reads a .bin or .hex input file into the payload.
func (im *Image) Load(path string) error {
	var data []byte
	if strings.EqualFold(filepath.Ext(path), ".hex") {
		h, err := ReadHex(path)
		if err != nil {
			return err
		}
		data = h.Binary()
		b := h.MinAddr()
		im.BaseAddr = &b
	} else {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			return fmt.Errorf("input file not found: %w", err)
		}
	}
	im.InFileData = data
	im.Payload = append([]byte(nil), data...)
	if im.PadHeader && im.HeaderSize > 0 {
		if im.BaseAddr != nil && *im.BaseAddr != 0 {
			b := *im.BaseAddr - uint32(im.HeaderSize)
			im.BaseAddr = &b
		}
		im.Payload = append(bytes.Repeat([]byte{im.ErasedVal}, im.HeaderSize), im.Payload...)
	}
	im.ImageSize = len(im.Payload) - im.HeaderSize
	return im.checkHeader()
}

func (im *Image) checkHeader() error {
	if im.HeaderSize > 0 && !im.PadHeader {
		if len(im.Payload) < im.HeaderSize {
			return errors.New("input is smaller than the header size")
		}
		for _, b := range im.Payload[:im.HeaderSize] {
			if b != 0 {
				return errors.New("header padding was not requested and image does not start with zeros")
			}
		}
	}
	return nil
}

func (im *Image) trailerSize() (int, error) {
	magicAlign := alignUp(16, im.MaxAlign)
	if im.OverwriteOnly {
		return im.MaxAlign*2 + magicAlign, nil
	}
	switch im.Align {
	case 1, 2, 4, 8, 16, 32, 64, 128:
	default:
		return 0, fmt.Errorf("invalid alignment: %d", im.Align)
	}
	t := im.MaxSectors * 3 * im.Align
	if im.EncKey != nil {
		keyLen := 16
		if im.SaveEncTLV {
			keyLen = im.enctlvLen
		}
		t += alignUp(keyLen, im.MaxAlign) * 2 // encryption keys
	}
	t += im.MaxAlign * 4 // image_ok/copy_done/swap_info/swap_size
	t += magicAlign
	return t, nil
}

func (im *Image) checkTrailer() error {
	if im.SlotSize <= 0 {
		return nil
	}
	ts, err := im.trailerSize()
	if err != nil {
		return err
	}
	if im.SlotSize-(len(im.Payload)+ts) < 0 {
		return fmt.Errorf("image size (0x%x) + trailer (0x%x) exceeds requested size 0x%x",
			len(im.Payload), ts, im.SlotSize)
	}
	return nil
}

func (im *Image) padTo(size int) error {
	ts, err := im.trailerSize()
	if err != nil {
		return err
	}
	pad := size - (len(im.Payload) + ts)
	if pad < 0 {
		return fmt.Errorf("image size (0x%x) + trailer (0x%x) exceeds requested size 0x%x",
			len(im.Payload), ts, size)
	}
	pb := bytes.Repeat([]byte{im.ErasedVal}, pad+ts-len(im.bootMagic))
	pb = append(pb, im.bootMagic...)
	if im.Confirm && !im.OverwriteOnly {
		idx := len(pb) - (alignUp(16, im.MaxAlign) + im.MaxAlign)
		pb[idx] = 0x01
	}
	im.Payload = append(im.Payload, pb...)
	return nil
}

// Save writes the image as .bin or .hex depending on the extension.
func (im *Image) Save(path string, hexAddr *uint32) error {
	if !strings.EqualFold(filepath.Ext(path), ".hex") {
		if im.Pad {
			if err := im.padTo(im.SlotSize); err != nil {
				return err
			}
		}
		return os.WriteFile(path, im.Payload, 0o644)
	}
	if im.BaseAddr == nil && hexAddr == nil {
		return errors.New("no address exists in input file neither was it provided by user")
	}
	if hexAddr != nil {
		im.BaseAddr = hexAddr
	}
	h := NewHexFile()
	h.Put(*im.BaseAddr, im.Payload)
	if im.Pad {
		ts, err := im.trailerSize()
		if err != nil {
			return err
		}
		trailerAddr := *im.BaseAddr + uint32(im.SlotSize) - uint32(ts)
		if (im.Test || im.Confirm) && !im.OverwriteOnly {
			idx := -(alignUp(16, im.MaxAlign) + im.MaxAlign)
			flag := bytes.Repeat([]byte{im.ErasedVal}, im.MaxAlign)
			if im.Confirm {
				flag[0] = 0x01
			}
			h.Put(uint32(int(trailerAddr)+ts+idx), flag)
		}
		h.Put(trailerAddr+uint32(ts-len(im.bootMagic)), im.bootMagic)
	}
	return h.Write(path)
}

func parseUUID(namespace []byte, value string) ([]byte, error) {
	re36 := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	re32 := regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	switch {
	case re36.MatchString(value):
		return hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	case re32.MatchString(value):
		return hex.DecodeString(value)
	}
	if namespace == nil {
		return nil, fmt.Errorf("unknown namespace for UUID: %s", value)
	}
	h := sha1.New()
	h.Write(namespace)
	h.Write([]byte(value))
	u := h.Sum(nil)[:16]
	u[6] = u[6]&0x0f | 0x50
	u[8] = u[8]&0x3f | 0x80
	return u, nil
}

// CreateOpts are the signing-related inputs of Image.Create.
type CreateOpts struct {
	Key          *Key
	PubKey       *Key // public key matching FixedSig
	PubKeyFormat string
	Deps         []Dependency
	Custom       []CustomTLV
	FixedSig     []byte
	Vector       string
	UserSHA      string
	Pure         bool
	PadSig       bool
	EncKey       *Key
	EncKeyLen    int // 128 or 256
	Clear        bool
	HMACSHA      string

	// Used by the compression flow.
	DontEncrypt      bool
	SkipTrailerCheck bool
	CompTLVs         []rawTLV
	KeepCompSize     bool
	CompFlags        uint32
}

type rawTLV struct {
	kind uint8
	val  []byte
}

func resolveSHA(key *Key, user string, pure bool) (string, uint8, error) {
	tlvFor := map[string]uint8{"256": tlvSHA256, "384": tlvSHA384, "512": tlvSHA512}
	if user == "" {
		user = "auto"
	}
	if key == nil {
		if user == "auto" {
			user = "256"
		}
		return user, tlvFor[user], nil
	}
	allowed := key.AllowedSHA(pure)
	if user == "auto" || pure {
		return allowed[0], tlvFor[allowed[0]], nil
	}
	for _, a := range allowed {
		if a == user {
			return user, tlvFor[user], nil
		}
	}
	return "", 0, fmt.Errorf("key can not be used with --sha %s; allowed sha are one of %v", user, allowed)
}

func (im *Image) Create(o CreateOpts) error {
	checkKey := o.Key
	if checkKey == nil {
		checkKey = o.PubKey
	}
	sha, hashTLV, err := resolveSHA(checkKey, o.UserSHA, o.Pure)
	if err != nil {
		return err
	}
	var pub []byte
	switch {
	case o.Key != nil:
		pub = o.Key.PublicBytes()
	case o.PubKey != nil:
		pub = o.PubKey.PublicBytes()
	}
	pubHash := digestOf(sha, pub)

	e := im.Order
	prot := &TLVArea{magic: tlvProtInfoMagic, order: e}
	if im.SecurityCnt != nil {
		b := make([]byte, 4)
		e.PutUint32(b, *im.SecurityCnt)
		prot.Add(tlvSecCnt, b)
	}
	for _, d := range o.Deps {
		b := make([]byte, 12)
		b[0] = d.ID
		b[4], b[5] = byte(d.Version.Major), byte(d.Version.Minor)
		e.PutUint16(b[6:], d.Version.Revision)
		e.PutUint32(b[8:], d.Version.Build)
		prot.Add(tlvDependency, b)
	}
	var vid []byte
	if im.VID != "" {
		dns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
		if vid, err = parseUUID(dns, im.VID); err != nil {
			return err
		}
		prot.Add(tlvUUIDVID, vid)
	}
	if im.CID != "" {
		cid, err := parseUUID(vid, im.CID)
		if err != nil {
			return err
		}
		prot.Add(tlvUUIDCID, cid)
	}
	comp := o.CompTLVs
	if o.KeepCompSize {
		b := make([]byte, 4)
		e.PutUint32(b, uint32(im.ImageSize))
		comp = append(append([]rawTLV(nil), comp...), rawTLV{tlvCompDecSize, b})
	}
	for _, c := range comp {
		prot.Add(c.kind, c.val)
	}
	for _, c := range o.Custom {
		prot.AddCustom(c.Tag, c.Value)
	}
	protSize := prot.size()

	im.EncKey = o.EncKey
	aes256 := o.EncKeyLen == 256
	encrypt := o.EncKey != nil && !o.DontEncrypt
	if o.EncKey != nil {
		if err := checkEncKey(o.Key, o.EncKey); err != nil {
			return err
		}
	}
	if encrypt {
		if r := len(im.Payload) % 16; r > 0 {
			im.Payload = append(im.Payload, make([]byte, 16-r)...)
		}
	}

	im.addHeader(protSize, o.EncKey != nil, aes256, o.CompFlags)
	protOff := len(im.Payload)
	protBytes := prot.Bytes()
	im.Payload = append(im.Payload, protBytes...)

	tlv := &TLVArea{magic: tlvInfoMagic, order: e}
	digest := digestOf(sha, im.Payload)
	tlv.Add(hashTLV, digest)
	im.ImageHash = digest
	if o.Pure {
		tlv.Add(tlvSigPure, []byte{1})
	}

	switch o.Vector {
	case "payload":
		fmt.Fprintln(os.Stderr, "imgtool: export payload")
		return nil
	case "digest":
		fmt.Fprintln(os.Stderr, "imgtool: export digest")
		im.Payload = digest
		return nil
	}

	if o.Key != nil || o.FixedSig != nil {
		if o.PubKeyFormat == "full" {
			tlv.Add(tlvPubKey, pub)
		} else {
			tlv.Add(tlvKeyHash, pubHash)
		}
		switch {
		case o.Key != nil && o.FixedSig == nil:
			sig, err := o.Key.Sign(im.Payload, digest, o.Pure, o.PadSig)
			if err != nil {
				return err
			}
			tlv.Add(o.Key.SigTLV(), sig)
			im.Signature = sig
		case o.FixedSig != nil && o.Key == nil:
			if o.PubKey == nil {
				return errors.New("public key of the fixed signature is not specified")
			}
			tlv.Add(o.PubKey.SigTLV(), o.FixedSig)
			im.Signature = o.FixedSig
		default:
			return errors.New("can not sign using key and provide fixed-signature at the same time")
		}
	}
	// The hash and signature cover the plaintext image and protected TLVs;
	// the latter are re-added after encryption.
	im.Payload = im.Payload[:protOff]

	if encrypt {
		plain := make([]byte, o.EncKeyLen/8)
		if _, err := rand.Read(plain); err != nil {
			return err
		}
		typ, enc, err := encryptImageKey(o.EncKey, plain, o.HMACSHA)
		if err != nil {
			return err
		}
		im.enctlvLen = len(enc)
		tlv.Add(typ, enc)
		if !o.Clear {
			ct, err := aesCTR(plain, im.Payload[im.HeaderSize:])
			if err != nil {
				return err
			}
			copy(im.Payload[im.HeaderSize:], ct)
		}
	}

	im.Payload = append(im.Payload, protBytes...)
	im.Payload = append(im.Payload, tlv.Bytes()...)
	if o.SkipTrailerCheck {
		return nil
	}
	return im.checkTrailer()
}

func (im *Image) addHeader(protSize int, encrypted, aes256 bool, compFlags uint32) {
	flags := compFlags
	if encrypted {
		if aes256 {
			flags |= flagEncAES256
		} else {
			flags |= flagEncAES128
		}
	}
	if im.LoadAddr != 0 {
		flags |= flagRAMLoad
	}
	if im.ROMFixed != 0 {
		flags |= flagROMFixed
	}
	if im.NonBootable {
		flags |= flagNonBootable
	}
	addr := im.LoadAddr
	if im.ROMFixed != 0 {
		addr = im.ROMFixed
	}
	h := make([]byte, imageHeaderSize)
	e := im.Order
	e.PutUint32(h[0:], imageMagic)
	e.PutUint32(h[4:], addr)
	e.PutUint16(h[8:], uint16(im.HeaderSize))
	e.PutUint16(h[10:], uint16(protSize))
	e.PutUint32(h[12:], uint32(len(im.Payload)-im.HeaderSize))
	e.PutUint32(h[16:], flags)
	h[20], h[21] = byte(im.Version.Major), byte(im.Version.Minor)
	e.PutUint16(h[22:], im.Version.Revision)
	e.PutUint32(h[24:], im.Version.Build)
	copy(im.Payload, h)
}
