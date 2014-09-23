// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"crypto/rand"
	"github.com/apptimistco/encr"
	"github.com/apptimistco/nbo"
	"io"
	"time"
)

type Obj struct {
	Owner  encr.Pub
	Author encr.Pub
	Time   time.Time
}

// Obj{}.ReadFrom *after* ReadMagicFrom()
func (obj *Obj) ReadFrom(r io.Reader) (n int64, err error) {
	var unique [32]byte
	ni, err := r.Read(unique[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = r.Read(obj.Owner[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = r.Read(obj.Author[:])
	if err != nil {
		return
	}
	n += int64(ni)
	var nanoepoch uint64
	ni, err = (nbo.Reader{r}).ReadNBO(&nanoepoch)
	if err != nil {
		return
	}
	n += 8
	sec := int64(time.Second)
	i := int64(nanoepoch)
	obj.Time = time.Unix(i/sec, i%sec)
	return
}

// Obj{}.WriteTo *after* WriteMagicTo
func (obj *Obj) WriteTo(w io.Writer) (n int64, err error) {
	var unique [32]byte
	ni, err := rand.Reader.Read(unique[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = w.Write(unique[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = w.Write(obj.Owner[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = w.Write(obj.Author[:])
	if err != nil {
		return
	}
	n += int64(ni)
	ni, err = (nbo.Writer{w}).WriteNBO(uint64(time.Now().UnixNano()))
	if err == nil {
		n += int64(ni)
	}
	return
}
