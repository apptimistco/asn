// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"io"
	"strconv"
)

const Latest = 0

type Version uint8

func (p *Version) ReadFrom(r io.Reader) (n int64, err error) {
	var b [1]byte
	ni, err := r.Read(b[:])
	if err == nil {
		n = int64(ni)
		*p = Version(b[0])
	}
	return
}
func (v Version) String() string {
	return strconv.Itoa(int(v))
}

func (v Version) WriteTo(w io.Writer) (n int64, err error) {
	b := []byte{byte(v)}
	ni, err := w.Write(b[:])
	if err == nil {
		n = int64(ni)
	}
	return
}
