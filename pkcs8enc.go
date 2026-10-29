package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
)

var (
	errPasswordRequired = errors.New("private key is encrypted")
	errBadPassword      = errors.New("bad decrypt: incorrect passphrase?")

	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESCBC    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidDESEDE3   = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// pbkdf2Iterations matches what pyca/cryptography (BestAvailableEncryption) emits.
const pbkdf2Iterations = 2048

type encryptedPrivateKeyInfo struct {
	Algo pkix.AlgorithmIdentifier
	Data []byte
}

type pbes2Params struct {
	KDF pkix.AlgorithmIdentifier
	Enc pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt      []byte
	Iter      int
	KeyLength int                      `asn1:"optional"`
	PRF       pkix.AlgorithmIdentifier `asn1:"optional"`
}

func prfHash(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case len(oid) == 0, oid.Equal(oidHMACSHA1):
		return sha1.New, nil
	case oid.Equal(oidHMACSHA224):
		return sha256.New224, nil
	case oid.Equal(oidHMACSHA256):
		return sha256.New, nil
	case oid.Equal(oidHMACSHA384):
		return sha512.New384, nil
	case oid.Equal(oidHMACSHA512):
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported PBKDF2 PRF %v", oid)
}

func cbcCipher(oid asn1.ObjectIdentifier) (func([]byte) (cipher.Block, error), int, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return aes.NewCipher, 16, nil
	case oid.Equal(oidAES192CBC):
		return aes.NewCipher, 24, nil
	case oid.Equal(oidAES256CBC):
		return aes.NewCipher, 32, nil
	case oid.Equal(oidDESEDE3):
		return des.NewTripleDESCipher, 24, nil
	case oid.Equal(oidDESCBC):
		return des.NewCipher, 8, nil
	}
	return nil, 0, fmt.Errorf("unsupported key encryption cipher %v", oid)
}

// decryptPKCS8 decrypts a PBES2/PBKDF2 "ENCRYPTED PRIVATE KEY" into plain PKCS#8 DER.
func decryptPKCS8(der, password []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &epki); err != nil {
		return nil, fmt.Errorf("invalid encrypted private key: %w", err)
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported private key encryption %v (only PBES2 is supported)", epki.Algo.Algorithm)
	}
	var p pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &p); err != nil {
		return nil, fmt.Errorf("invalid PBES2 parameters: %w", err)
	}
	if !p.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported key derivation function %v (only PBKDF2 is supported)", p.KDF.Algorithm)
	}
	var kp pbkdf2Params
	if _, err := asn1.Unmarshal(p.KDF.Parameters.FullBytes, &kp); err != nil {
		return nil, fmt.Errorf("invalid PBKDF2 parameters: %w", err)
	}
	h, err := prfHash(kp.PRF.Algorithm)
	if err != nil {
		return nil, err
	}
	newCipher, keyLen, err := cbcCipher(p.Enc.Algorithm)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if _, err := asn1.Unmarshal(p.Enc.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("invalid cipher IV: %w", err)
	}
	if kp.KeyLength != 0 && kp.KeyLength != keyLen {
		return nil, errors.New("PBKDF2 key length does not match the cipher")
	}
	key, err := pbkdf2.Key(h, string(password), kp.Salt, kp.Iter, keyLen)
	if err != nil {
		return nil, err
	}
	blk, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := blk.BlockSize()
	if len(iv) != bs || len(epki.Data) == 0 || len(epki.Data)%bs != 0 {
		return nil, errors.New("invalid encrypted private key data")
	}
	out := make([]byte, len(epki.Data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, epki.Data)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > bs {
		return nil, errBadPassword
	}
	for _, c := range out[len(out)-pad:] {
		if int(c) != pad {
			return nil, errBadPassword
		}
	}
	return out[:len(out)-pad], nil
}

// encryptPKCS8 wraps plain PKCS#8 DER with PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC),
// the same scheme pyca/cryptography's BestAvailableEncryption uses.
func encryptPKCS8(der, password []byte) ([]byte, error) {
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, string(password), salt, pbkdf2Iterations, 32)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	pad := aes.BlockSize - len(der)%aes.BlockSize
	data := append(append([]byte(nil), der...), make([]byte, pad)...)
	for i := len(der); i < len(data); i++ {
		data[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(data, data)

	asn1Null := asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
	kdf, err := asn1.Marshal(pbkdf2Params{Salt: salt, Iter: pbkdf2Iterations,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1Null}})
	if err != nil {
		return nil, err
	}
	ivDER, _ := asn1.Marshal(iv)
	params, err := asn1.Marshal(pbes2Params{
		KDF: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		Enc: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		Data: data,
	})
}
