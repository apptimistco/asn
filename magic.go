// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"bytes"
	"errors"
	"io"
)

const (
	secretMagic = "asnmagic"
	MagicSz     = len(secretMagic)
)

var ErrNotMagic = errors.New("Not Magic")

func IsMagic(m []byte) bool {
	return bytes.Equal(m, []byte(secretMagic))
}

// ReadMagicFrom *after* Id{}.ReadFrom(w)
func ReadMagicFrom(r io.Reader) (n int64, err error) {
	var b [MagicSz]byte
	ni, err := r.Read(b[:])
	if err != nil {
		return
	}
	n = int64(ni)
	if !IsMagic(b[:]) {
		err = ErrNotMagic
	}
	return
}

// WriteMagicTo *after* Id{}.WriteTo(w)
func WriteMagicTo(w io.Writer) (n int64, err error) {
	ni, err := w.Write([]byte(secretMagic))
	if err != nil {
		return
	}
	n = int64(ni)
	return
}
