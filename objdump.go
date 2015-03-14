// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
)

// ObjDump expects that reader has read Version and Id
func ObjDump(w io.Writer, r io.Reader) (err error) {
	blob, err := NewBlobFrom(r)
	if err != nil {
		return
	}
	fmt.Fprintln(w, blob)
	switch blob.Name {
	case AsnAuth:
		auth := new(PubAuth)
		auth.ReadFrom(r)
		fmt.Fprintln(w, "auth:", auth)
	case AsnAuthor:
		author := new(PubEncr)
		author.ReadFrom(r)
		fmt.Fprintln(w, "author:", author)
	case AsnMark:
		mark := new(Mark)
		mark.ReadFrom(r)
		fmt.Fprintln(w, mark)
	case AsnEditors, AsnInvites, AsnModerators, AsnSubscribers:
		l := new(PubEncrList)
		l.ReadFrom(r)
		fmt.Fprintln(w, l)
	case "", AsnMessages, AsnMessages + "/":
		_, err = io.Copy(w, r)
		w.Write(NL)
	default:
		var n int64
		if n, err = io.Copy(w, r); err != nil {
			fmt.Fprintln(w, "len:", n)
		}
	}
	return
}
