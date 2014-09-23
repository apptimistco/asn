// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

const (
	SumSz = sha512.Size
)

type Sum [SumSz]uint8

// NewSum from given []byte or named file
func NewSumBytes(b []byte) Sum {
	return Sum(sha512.Sum512(b))
}

func NewSumReader(r io.Reader) (sum Sum) {
	h := sha512.New()
	io.Copy(h, r)
	copy(sum[:], h.Sum([]byte{}))
	return
}

func (sum *Sum) String() string { return hex.EncodeToString((*sum)[:]) }
