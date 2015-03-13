// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
	"path/filepath"
)

const (
	SumSz = sha512.Size
)

type Sum [SumSz]uint8

// NewSum of []byte
func NewSumBytes(b []byte) Sum {
	return Sum(sha512.Sum512(b))
}

// NewSumFrom reader
func NewSumOf(r io.Reader) (sum *Sum) {
	sum = new(Sum)
	h := sha512.New()
	io.Copy(h, r)
	copy(sum[:], h.Sum([]byte{}))
	return
}

func (sum *Sum) FullString() string {
	return hex.EncodeToString((*sum)[:])
}

func (sum *Sum) ShortString() string {
	return sum.FullString()[:8]
}

func (sum *Sum) String() string {
	return Ellipsis(sum.ShortString())
}

func (sum *Sum) PN() string {
	s := sum.FullString()
	return filepath.Join(s[:ReposTopSz], s[ReposTopSz:])
}
