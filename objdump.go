// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

// ObjDump expects that reader has read Version and Id
func ObjDump(w io.Writer, r io.Reader) (err error) {
	blob, err := NewBlobFrom(r)
	if err != nil {
		return
	}
	if blob.Name != AsnMark {
		fmt.Fprintln(w, blob)
	}
	for _, fn := range AsnPubEncrLists {
		if strings.HasPrefix(blob.Name, fn+"/") {
			// only show blob header
			return
		} else if blob.Name == fn {
			l := new(PubEncrList)
			l.ReadFrom(r)
			fmt.Fprintln(w, l)
			return
		}
	}
	switch blob.Name {
	case AsnAuth:
		auth := new(PubAuth)
		auth.ReadFrom(r)
		fmt.Fprintln(w, "auth:", auth)
	case AsnAuthor:
		author := new(PubEncr)
		author.ReadFrom(r)
		fmt.Fprintln(w, "author:", author)
	case AsnID:
		id := NewCacheBuffer()
		id.ReadFrom(r)
		fmt.Fprintln(w, "id:", id)
	case AsnMark:
		mark := new(Mark)
		mark.ReadFrom(r)
		fmt.Fprintln(w, mark)
	case AsnUser:
		_, err = io.Copy(w, r)
		w.Write(NL)
	default:
		var n int64
		n, err = io.Copy(ioutil.Discard, r)
		fmt.Fprintln(w, "len:", n)
	}
	return
}
