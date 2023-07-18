// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package base58

import (
	"crypto/sha256"
	"errors"

	"github.com/hc/blake256"
)

// ErrChecksum indicates that the checksum of a check-encoded string does not verify against
// the checksum.
var ErrChecksum = errors.New("checksum error")

// ErrInvalidFormat indicates that the check-encoded string has an invalid format.
var ErrInvalidFormat = errors.New("invalid format: version and/or checksum bytes missing")

// checksum: first four bytes of sha256^2
func checksum(input []byte) (cksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(cksum[:], h2[:4])
	return
}

// CheckEncode prepends a version byte and appends a four byte checksum.
func CheckEncode(input []byte, version byte) string {
	b := make([]byte, 0, 1+len(input)+4)
	b = append(b, version)
	b = append(b, input[:]...)
	cksum := checksum(b)
	b = append(b, cksum[:]...)
	return Encode(b)
}
func CheckInputByte(input []byte, version byte) []byte {
	b := make([]byte, 0, 1+len(input)+4)
	b = append(b, version)
	b = append(b, input[:]...)
	cksum := checksum(b)
	b = append(b, cksum[:]...)
	return b
}
func CheckONTEncode(input []byte, version []byte) string {
	b := make([]byte, 0, 1+len(input)+4)
	b = append(b, version[:]...)
	b = append(b, input[:]...)
	cksum := checksum(b)
	b = append(b, cksum[:]...)
	return Encode(b)
}

func CheckHCDecode(input string) (result []byte, version [2]byte, err error) {
	decoded := Decode(input)
	if len(decoded) < 6 {
		return nil, [2]byte{0, 0}, ErrInvalidFormat
	}
	version = [2]byte{decoded[0], decoded[1]}
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if checkhcsum(decoded[:len(decoded)-4]) != cksum {
		return nil, [2]byte{0, 0}, ErrChecksum
	}
	payload := decoded[2 : len(decoded)-4]
	result = append(result, payload...)
	return
}
func checkhcsum(input []byte) (cksum [4]byte) {
	h := blake256.New()
	h.Write(input)
	intermediateHash := h.Sum(nil)
	h.Reset()
	h.Write(intermediateHash)
	finalHash := h.Sum(nil)
	copy(cksum[:], finalHash[:])
	return
}

// CheckDecode decodes a string that was encoded with CheckEncode and verifies the checksum.
func CheckDecode(input string) (result []byte, version byte, err error) {
	decoded := Decode(input)
	if len(decoded) < 5 {
		return nil, 0, ErrInvalidFormat
	}
	version = decoded[0]
	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])
	if checksum(decoded[:len(decoded)-4]) != cksum {
		return nil, 0, ErrChecksum
	}
	payload := decoded[1 : len(decoded)-4]
	result = append(result, payload...)
	return
}
