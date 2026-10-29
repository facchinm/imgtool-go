package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootRecordCBOR(t *testing.T) {
	// Generated with upstream boot_record.create_sw_component_data (cbor2).
	const want = "a501644e5350450465312e322e33055820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f06665348413235360258200000000000000000000000000000000000000000000000000000000000000000"
	signer := make([]byte, 32)
	for i := range signer {
		signer[i] = byte(i)
	}
	if got := hex.EncodeToString(bootRecordCBOR("NSPE", "1.2.3", signer, "SHA256", make([]byte, 32))); got != want {
		t.Fatalf("got %s", got)
	}
}

func TestEncryptedKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	for _, typ := range keyTypes {
		k, err := GenerateKey(typ)
		if err != nil {
			t.Fatal(err)
		}
		p, err := k.PrivatePEM([]byte("s3cret"))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, typ+".pem")
		os.WriteFile(path, p, 0o600)
		if _, err := LoadKey(path); !errors.Is(err, errPasswordRequired) {
			t.Fatalf("%s: expected errPasswordRequired, got %v", typ, err)
		}
		if _, err := LoadKeyPassword(path, []byte("wrong")); err == nil {
			t.Fatalf("%s: wrong password accepted", typ)
		}
		k2, err := LoadKeyPassword(path, []byte("s3cret"))
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if !bytes.Equal(k.PublicBytes(), k2.PublicBytes()) {
			t.Fatalf("%s: public key mismatch", typ)
		}
	}
}

func TestYAMLScalar(t *testing.T) {
	for in, want := range map[string]string{
		"out.bin": "out.bin", "1.2.3+0": "1.2.3+0", "yes": "'yes'", "1.0": "'1.0'", "012": "'012'",
		"a: b": "'a: b'", "-x": "-x", "- x": "'- x'", "": "''", "é": `"\xE9"`, "it's #1": "'it''s #1'", "a'b": "a'b", "x#y": "x#y", "a:": "'a:'",
	} {
		if got := yamlScalarString(in); got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
	}
}

func TestDumpInfoYAML(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "app.bin")
	os.WriteFile(in, bytes.Repeat([]byte{0xaa}, 100), 0o644)
	out := filepath.Join(dir, "app-signed.bin")
	if err := cmdSign([]string{"-v", "1.2.3", "-H", "0x20", "--pad-header", "-S", "0x1000", "-s", "5",
		"--boot-record", "NSPE", "--pad", in, out}); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	f := filepath.Join(dir, "info.yaml")
	if err := cmdDumpinfo([]string{"-o", f, out}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	sb.Write(b)
	for _, want := range []string{"filename: app-signed.bin\n", "  version: 1.2.3+0\n",
		"  - type: 96\n    type_name: BOOT_RECORD\n", "trailer:\n  magic: !!binary |\n    d8KV82DS7381UlAPLLZ5gA==\n"} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("missing %q in:\n%s", want, sb.String())
		}
	}
}
