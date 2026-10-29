package main

import (
	"bytes"

	"github.com/ulikunitz/xz/lzma"
)

const (
	flagCompLZMA2      = 0x400
	flagCompARMThumb   = 0x800
	compDefaultDictCap = 131072
	compDefaultPB      = 2
	compDefaultLC      = 3
	compDefaultLP      = 1
)

// armThumbEncode applies the xz ARM-Thumb BCJ filter (start offset 0) in place.
func armThumbEncode(buf []byte) {
	for i := 0; i+4 <= len(buf); i += 2 {
		if buf[i+1]&0xf8 != 0xf0 || buf[i+3]&0xf8 != 0xf8 {
			continue
		}
		src := (uint32(buf[i+1])&7)<<19 | uint32(buf[i])<<11 | (uint32(buf[i+3])&7)<<8 | uint32(buf[i+2])
		dest := (uint32(i) + 4 + src<<1) >> 1
		buf[i+1] = 0xf0 | byte(dest>>19)&7
		buf[i] = byte(dest >> 11)
		buf[i+3] = 0xf8 | byte(dest>>8)&7
		buf[i+2] = byte(dest)
		i += 2
	}
}

// compressLZMA2 returns a raw LZMA2 stream (no container) with the parameters
// MCUboot's decompressor expects.
func compressLZMA2(data []byte, armThumb bool) ([]byte, error) {
	in := append([]byte(nil), data...)
	if armThumb {
		armThumbEncode(in)
	}
	var out bytes.Buffer
	w, err := lzma.Writer2Config{
		Properties: &lzma.Properties{LC: compDefaultLC, LP: compDefaultLP, PB: compDefaultPB},
		DictCap:    compDefaultDictCap,
		Matcher:    lzma.HashTable4,
	}.NewWriter2(&out)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(in); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// lzma2Header is the 2-byte (dictionary size, properties) header MCUboot
// expects in front of the raw LZMA2 stream.
func lzma2Header() []byte {
	var dict byte
	for i := 0; i < 40; i++ {
		if compDefaultDictCap <= (2|(i&1))<<(i/2+11) {
			dict = byte(i)
			break
		}
	}
	return []byte{dict, byte((compDefaultPB*5+compDefaultLP)*9 + compDefaultLC)}
}

// LoadCompressed installs an already compressed body as the image payload.
func (im *Image) LoadCompressed(data, header []byte) {
	im.Payload = append(append([]byte(nil), header...), data...)
	im.ImageSize = len(im.Payload)
	if im.HeaderSize > 0 {
		fill := byte(0)
		if im.PadHeader {
			fill = im.ErasedVal
		}
		im.Payload = append(bytes.Repeat([]byte{fill}, im.HeaderSize), im.Payload...)
	}
}

// BuildCompressed mirrors upstream's two-pass flow: the uncompressed image is
// built first to obtain its hash and signature, which are recorded as
// protected TLVs of the compressed image. Returns nil if compression does not
// shrink the image, in which case the caller should build it normally.
func BuildCompressed(newImg func() (*Image, error), infile, compression string, o CreateOpts) (*Image, error) {
	first, err := newImg()
	if err != nil {
		return nil, err
	}
	if err := first.Load(infile); err != nil {
		return nil, err
	}
	p1 := o
	p1.DontEncrypt, p1.SkipTrailerCheck = true, true
	if err := first.Create(p1); err != nil {
		return nil, err
	}

	data := first.InFileData
	if !first.PadHeader {
		data = data[first.HeaderSize:]
	}
	armThumb := compression == "lzma2armthumb"
	comp, err := compressLZMA2(data, armThumb)
	if err != nil {
		return nil, err
	}
	logf("compressed image size: %d bytes\n", len(comp))
	logf("original image size: %d bytes\n", len(data))

	u32 := func(v int) []byte {
		b := make([]byte, 4)
		first.Order.PutUint32(b, uint32(v))
		return b
	}
	tlvs := []rawTLV{{tlvDecompSize, u32(first.ImageSize)}, {tlvDecompSHA, first.ImageHash}}
	size := 4 + len(first.ImageHash)
	if len(first.Signature) > 0 {
		tlvs = append(tlvs, rawTLV{tlvDecompSig, first.Signature})
		size += len(first.Signature)
	}
	if len(comp)+size >= len(data) {
		return nil, nil
	}

	ci, err := newImg()
	if err != nil {
		return nil, err
	}
	ci.LoadCompressed(comp, lzma2Header())
	ci.BaseAddr = first.BaseAddr
	o.CompTLVs = tlvs
	o.KeepCompSize = o.EncKey != nil
	o.CompFlags = flagCompLZMA2
	if armThumb {
		o.CompFlags |= flagCompARMThumb
	}
	if err := ci.Create(o); err != nil {
		return nil, err
	}
	return ci, nil
}
