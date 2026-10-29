package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
)

func x509MarshalPKCS8(k any) ([]byte, error) { return x509.MarshalPKCS8PrivateKey(k) }

// marshalRSAPrivate emits PKCS#1; minimal keeps only N/E/D/P/Q (no CRT params).
func marshalRSAPrivate(k *rsa.PrivateKey, minimal bool) ([]byte, error) {
	if !minimal {
		return x509.MarshalPKCS1PrivateKey(k), nil
	}
	return asn1.Marshal(struct {
		Version int
		N       *big.Int
		E       int
		D, P, Q *big.Int
	}{0, k.N, k.E, k.D, k.Primes[0], k.Primes[1]})
}

type ecPrivateKey struct {
	Version int
	Private []byte
	Params  asn1.RawValue  `asn1:"optional,explicit,tag:0"`
	Public  asn1.BitString `asn1:"optional,explicit,tag:1"`
}

type pkcs8Info struct {
	Version int
	Algo    asn1.RawValue
	Private []byte
}

// marshalECPrivate emits PKCS#8 or SEC1; minimal drops the optional public key.
func marshalECPrivate(k *ecdsa.PrivateKey, minimal, pkcs8 bool) ([]byte, error) {
	var der []byte
	var err error
	if pkcs8 {
		der, err = x509.MarshalPKCS8PrivateKey(k)
	} else {
		der, err = x509.MarshalECPrivateKey(k)
	}
	if err != nil || !minimal {
		return der, err
	}
	strip := func(inner []byte) ([]byte, error) {
		var ec ecPrivateKey
		if _, err := asn1.Unmarshal(inner, &ec); err != nil {
			return nil, err
		}
		ec.Public = asn1.BitString{}
		type out struct {
			Version int
			Private []byte
			Params  asn1.RawValue `asn1:"optional,explicit,tag:0"`
		}
		return asn1.Marshal(out{ec.Version, ec.Private, ec.Params})
	}
	if !pkcs8 {
		return strip(der)
	}
	var p pkcs8Info
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		return nil, err
	}
	if p.Private, err = strip(p.Private); err != nil {
		return nil, err
	}
	return asn1.Marshal(p)
}
