// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"sync"
)

var req struct {
	sync.Mutex
	n uint64
}

type Req [8]byte

func NextReq() (r Req) {
	req.Lock()
	defer req.Unlock()
	binary.BigEndian.PutUint64(r[:], req.n)
	req.n += 1
	return
}

func NewReqString(s string) (r Req) {
	copy(r[:], []byte(s))
	return
}

func (req *Req) ReadFrom(r io.Reader) (n int64, err error) {
	ni, err := r.Read(req[:])
	if err == nil {
		n = int64(ni)
	}
	return
}

func (req Req) String() string {
	return hex.EncodeToString(req[:])
}

func (req Req) WriteTo(w io.Writer) (n int64, err error) {
	ni, err := w.Write(req[:])
	if err == nil {
		n = int64(ni)
	}
	return
}
