package main

import "encoding/binary"

const maxSwTypeLength = 12

// PSA attestation software component property IDs.
const (
	swcType                   = 1
	swcMeasurementValue       = 2
	swcVersion                = 4
	swcSignerID               = 5
	swcMeasurementDescription = 6
)

func cborHead(major byte, n uint64) []byte {
	major <<= 5
	switch {
	case n < 24:
		return []byte{major | byte(n)}
	case n <= 0xff:
		return []byte{major | 24, byte(n)}
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16([]byte{major | 25}, uint16(n))
	case n <= 0xffffffff:
		return binary.BigEndian.AppendUint32([]byte{major | 26}, uint32(n))
	}
	return binary.BigEndian.AppendUint64([]byte{major | 27}, n)
}

func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }
func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }

// bootRecordCBOR encodes the boot record exactly like upstream (cbor2, insertion
// order). The measurement value must stay last: the bootloader patches it in place.
func bootRecordCBOR(swType, version string, signerID []byte, measDesc string, measValue []byte) []byte {
	out := cborHead(5, 5)
	out = append(append(out, cborHead(0, swcType)...), cborText(swType)...)
	out = append(append(out, cborHead(0, swcVersion)...), cborText(version)...)
	out = append(append(out, cborHead(0, swcSignerID)...), cborBytes(signerID)...)
	out = append(append(out, cborHead(0, swcMeasurementDescription)...), cborText(measDesc)...)
	out = append(append(out, cborHead(0, swcMeasurementValue)...), cborBytes(measValue)...)
	return out
}
