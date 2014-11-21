// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"io"
	"strconv"
)

type Requester [8]byte

func NewRequesterString(s string) (r Requester) {
	copy(r[:], []byte(s))
	return
}

func (req *Requester) ReadFrom(r io.Reader) (n int64, err error) {
	ni, err := r.Read(req[:])
	if err == nil {
		n = int64(ni)
	}
	return
}

func (req Requester) String() string {
	return strconv.QuoteToASCII(string(req[:]))
}

func (req Requester) WriteTo(w io.Writer) (n int64, err error) {
	ni, err := w.Write(req[:])
	if err == nil {
		n = int64(ni)
	}
	return
}
