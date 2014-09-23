// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"io"
	"strings"
)

type Name string

func (name *Name) Equal(s string) bool { return string(*name) == s }

func (name *Name) Index() (s string) {
	if i := strings.Index(string(*name), "/"); i > 0 {
		s = string(*name)[:i]
	}
	return
}

// Name{}.ReadFrom *after* Obj{}.ReadFrom
func (name *Name) ReadFrom(r io.Reader) (n int64, err error) {
	var (
		namelen int
		b       [256]byte
	)
	ni, err := r.Read(b[:1])
	if err != nil {
		return
	}
	n += int64(ni)
	if namelen = int(b[0]); namelen > 0 {
		ni, err = r.Read(b[:namelen])
		if err != nil {
			return
		}
		n += int64(ni)
		*name = Name(b[:namelen])
	}
	return
}

// Name{}.WriteTo *after* Obj{}.WriteTo
func (name *Name) WriteTo(w io.Writer) (n int64, err error) {
	b := [1]byte{byte(len(*name))}
	ni, err := w.Write(b[:])
	if err != nil {
		return
	}
	if b[0] > 0 {
		n += int64(ni)
		ni, err = w.Write([]byte(string(*name)[:]))
		if err != nil {
			return
		}
		n += int64(ni)
	}
	return
}
