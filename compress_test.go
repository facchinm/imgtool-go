package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz/lzma"
)

func TestCompressLZMA2RoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("firmware block 0123456789 "), 4000)
	comp, err := compressLZMA2(data, false)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := lzma.Reader2Config{DictCap: compDefaultDictCap}.NewReader2(bytes.NewReader(comp))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rd)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip failed: %v", err)
	}
	if h := lzma2Header(); h[0] != 10 || h[1] != 102 {
		t.Fatalf("unexpected header % x", h)
	}
}

func TestCompressedImageFlags(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "app.bin")
	os.WriteFile(in, bytes.Repeat([]byte("abcd"), 2000), 0o644)
	out := filepath.Join(dir, "out.bin")
	if err := cmdSign([]string{"-v", "1.0", "-H", "0x200", "-S", "0x10000", "--pad-header",
		"--compression", "lzma2armthumb", in, out}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if flags := uint32(b[16]) | uint32(b[17])<<8; flags&flagCompLZMA2 == 0 || flags&flagCompARMThumb == 0 {
		t.Fatalf("compression flags missing: %#x", flags)
	}
	if res, _, _, _, err := VerifyImage(out, nil); err != nil || res != VerifyOK {
		t.Fatalf("verify = %v, %v", res, err)
	}
}
