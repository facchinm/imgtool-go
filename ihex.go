package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

// HexFile is a sparse memory image read from / written to Intel HEX.
type HexFile struct {
	mem map[uint32]byte
}

func NewHexFile() *HexFile { return &HexFile{mem: map[uint32]byte{}} }

func (h *HexFile) Put(addr uint32, data []byte) {
	for i, b := range data {
		h.mem[addr+uint32(i)] = b
	}
}

func (h *HexFile) addrs() []uint32 {
	a := make([]uint32, 0, len(h.mem))
	for k := range h.mem {
		a = append(a, k)
	}
	sort.Slice(a, func(i, j int) bool { return a[i] < a[j] })
	return a
}

// MinAddr returns the lowest defined address.
func (h *HexFile) MinAddr() uint32 {
	a := h.addrs()
	if len(a) == 0 {
		return 0
	}
	return a[0]
}

// Binary returns the contiguous range min..max, gaps filled with 0xff.
func (h *HexFile) Binary() []byte {
	a := h.addrs()
	if len(a) == 0 {
		return nil
	}
	lo, hi := a[0], a[len(a)-1]
	out := bytes.Repeat([]byte{0xff}, int(hi-lo)+1)
	for k, v := range h.mem {
		out[k-lo] = v
	}
	return out
}

func ReadHex(path string) (*HexFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := NewHexFile()
	var base uint32
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line[0] != ':' {
			return nil, fmt.Errorf("%s:%d: invalid hex record", path, ln)
		}
		raw, err := hex.DecodeString(line[1:])
		if err != nil || len(raw) < 5 || len(raw) != int(raw[0])+5 {
			return nil, fmt.Errorf("%s:%d: malformed hex record", path, ln)
		}
		var sum byte
		for _, b := range raw {
			sum += b
		}
		if sum != 0 {
			return nil, fmt.Errorf("%s:%d: checksum mismatch", path, ln)
		}
		n := int(raw[0])
		off := uint32(raw[1])<<8 | uint32(raw[2])
		data := raw[4 : 4+n]
		switch raw[3] {
		case 0x00:
			h.Put(base+off, data)
		case 0x01:
			return h, nil
		case 0x02:
			base = (uint32(data[0])<<8 | uint32(data[1])) << 4
		case 0x04:
			base = (uint32(data[0])<<8 | uint32(data[1])) << 16
		}
	}
	return h, sc.Err()
}

func hexRecord(typ byte, off uint16, data []byte) string {
	rec := []byte{byte(len(data)), byte(off >> 8), byte(off), typ}
	rec = append(rec, data...)
	var sum byte
	for _, b := range rec {
		sum += b
	}
	rec = append(rec, -sum)
	return ":" + strings.ToUpper(hex.EncodeToString(rec)) + "\n"
}

func (h *HexFile) Write(path string) error {
	var sb strings.Builder
	a := h.addrs()
	var curHi uint32 = 0
	for i := 0; i < len(a); {
		start := a[i]
		hi := start >> 16
		if hi != curHi {
			sb.WriteString(hexRecord(0x04, 0, []byte{byte(hi >> 8), byte(hi)}))
			curHi = hi
		}
		var chunk []byte
		j := i
		for j < len(a) && len(chunk) < 16 && a[j] == start+uint32(len(chunk)) && a[j]>>16 == hi {
			chunk = append(chunk, h.mem[a[j]])
			j++
		}
		sb.WriteString(hexRecord(0x00, uint16(start), chunk))
		i = j
	}
	sb.WriteString(hexRecord(0x01, 0, nil))
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
