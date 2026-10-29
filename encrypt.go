package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

const (
	tlvEncRSA2048      = 0x30
	tlvEncKW           = 0x31
	tlvEncEC256        = 0x32
	tlvEncX25519       = 0x33
	tlvEncX25519SHA512 = 0x34

	flagEncAES128 = 0x04
	flagEncAES256 = 0x08
)

// aesCTR applies AES-CTR with the all-zero nonce MCUboot expects.
func aesCTR(key, data []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCTR(blk, make([]byte, aes.BlockSize)).XORKeyStream(out, data)
	return out, nil
}

// checkEncKey validates that enc can be used to wrap an image key.
func checkEncKey(sign, enc *Key) error {
	switch enc.Kind {
	case KindRSA, KindECDSA256, KindX25519:
	default:
		return errors.New("unsupported encryption key type; use an RSA, ECDSA-P256 or X25519 key")
	}
	if sign != nil && ((sign.Kind == KindECDSA256 && enc.Kind != KindECDSA256) ||
		(sign.Kind == KindECDSA384 && enc.Kind != KindECDSA384) ||
		(sign.Kind == KindRSA && enc.Kind != KindRSA)) {
		return errors.New("signing and encryption must use the same type of key")
	}
	return nil
}

// encryptImageKey wraps the plain AES key for the bootloader and returns the
// TLV type and payload.
func encryptImageKey(enc *Key, plain []byte, hmacSHA string) (uint8, []byte, error) {
	if enc.Kind == KindRSA {
		ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, enc.Pub.(*rsa.PublicKey), plain, nil)
		return tlvEncRSA2048, ct, err
	}

	var hf func() hash.Hash
	switch hmacSHA {
	case "", "auto", "256":
		hmacSHA, hf = "256", sha256.New
	case "512":
		if enc.Kind != KindX25519 {
			return 0, nil, errors.New("currently only ECIES-X25519 supports HMAC-SHA512")
		}
		hf = sha512.New
	default:
		return 0, nil, errors.New("unsupported HMAC-SHA")
	}

	var peer *ecdh.PublicKey
	var eph *ecdh.PrivateKey
	var err error
	var tlvType uint8
	switch enc.Kind {
	case KindECDSA256:
		peer, err = enc.Pub.(*ecdsa.PublicKey).ECDH()
		if err != nil {
			return 0, nil, err
		}
		eph, err = ecdh.P256().GenerateKey(rand.Reader)
		tlvType = tlvEncEC256
	default:
		peer = enc.Pub.(*ecdh.PublicKey)
		eph, err = ecdh.X25519().GenerateKey(rand.Reader)
		tlvType = tlvEncX25519
		if hmacSHA == "512" {
			tlvType = tlvEncX25519SHA512
		}
	}
	if err != nil {
		return 0, nil, err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return 0, nil, err
	}
	keyLen, macLen := len(plain), hf().Size()
	derived, err := hkdf.Key(hf, shared, nil, "MCUBoot_ECIES_v1", keyLen+macLen)
	if err != nil {
		return 0, nil, err
	}
	cipherKey, err := aesCTR(derived[:keyLen], plain)
	if err != nil {
		return 0, nil, err
	}
	m := hmac.New(hf, derived[keyLen:])
	m.Write(cipherKey)

	out := append(eph.PublicKey().Bytes(), m.Sum(nil)...)
	return tlvType, append(out, cipherKey...), nil
}

// PrivateBytes returns the DER private key as emitted by `getpriv`.
func (k *Key) PrivateBytes(minimal bool, format string) ([]byte, error) {
	switch k.Kind {
	case KindEd25519:
		return nil, errors.New("operation not supported with ed25519 keys")
	case KindX25519:
		if format != "" && format != "pkcs8" {
			return nil, fmt.Errorf("x25519 does not support %s", format)
		}
		return x509MarshalPKCS8(k.ECDHPriv)
	case KindRSA:
		if format != "" && format != "openssl" {
			return nil, fmt.Errorf("rsa does not support %s", format)
		}
		return marshalRSAPrivate(k.Priv.(*rsa.PrivateKey), minimal)
	}
	if format == "" {
		format = "pkcs8"
	}
	if format != "pkcs8" && format != "openssl" {
		return nil, fmt.Errorf("%s does not support %s", k.ShortName(), format)
	}
	return marshalECPrivate(k.Priv.(*ecdsa.PrivateKey), minimal, format == "pkcs8")
}
