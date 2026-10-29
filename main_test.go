package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "app.bin")
	if err := os.WriteFile(in, make([]byte, 1000), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, typ := range keyTypes[:5] {
		key, err := GenerateKey(typ)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes, _ := key.PrivatePEM()
		kf := filepath.Join(dir, typ+".pem")
		os.WriteFile(kf, pemBytes, 0o600)
		out := filepath.Join(dir, typ+".img")
		if err := cmdSign([]string{"-k", kf, "-v", "1.2.3", "-H", "0x200", "-S", "0x10000",
			"--pad-header", "--pad", in, out}); err != nil {
			t.Fatalf("%s: sign: %v", typ, err)
		}
		pub, err := LoadKey(kf)
		if err != nil {
			t.Fatal(err)
		}
		res, ver, _, _, err := VerifyImage(out, pub)
		if err != nil || res != VerifyOK || ver.String() != "1.2.3+0" {
			t.Fatalf("%s: verify = %v %v %v", typ, res, ver, err)
		}

		img, _ := os.ReadFile(out)
		img[0x300] ^= 1
		os.WriteFile(out, img, 0o644)
		if res, _, _, _, _ := VerifyImage(out, pub); res != VerifyInvalidHash {
			t.Fatalf("%s: tampered image result = %v", typ, res)
		}
	}
}

func TestDecodeVersion(t *testing.T) {
	v, err := DecodeVersion("1.2.3+4")
	if err != nil || v != (Version{1, 2, 3, 4}) {
		t.Fatalf("got %v, %v", v, err)
	}
	if _, err := DecodeVersion("01.2"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEncryptedImageFlagsAndTLV(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "app.bin")
	os.WriteFile(in, make([]byte, 1001), 0o644)
	sk, _ := GenerateKey("ed25519")
	sp, _ := sk.PrivatePEM()
	skf := filepath.Join(dir, "sign.pem")
	os.WriteFile(skf, sp, 0o600)
	for typ, want := range map[string]byte{"x25519": tlvEncX25519, "rsa-2048": tlvEncRSA2048} {
		ek, _ := GenerateKey(typ)
		ekf := filepath.Join(dir, typ+".pem")
		os.WriteFile(ekf, ek.PublicPEM(), 0o644)
		out := filepath.Join(dir, typ+".img")
		if err := cmdSign([]string{"-k", skf, "-E", ekf, "--encrypt-keylen", "256", "-v", "1.0",
			"-H", "0x200", "-S", "0x10000", "--pad-header", in, out}); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(out)
		if b[16]&flagEncAES256 == 0 {
			t.Fatalf("%s: AES-256 flag missing", typ)
		}
		if b[12]%16 != 0 && len(b) > 0 && (int(b[12])|int(b[13])<<8)%16 != 0 {
			t.Fatalf("%s: image size not 16-byte aligned", typ)
		}
		if !bytes.Contains(b, []byte{want, 0}) {
			t.Fatalf("%s: enc TLV missing", typ)
		}
	}
}
