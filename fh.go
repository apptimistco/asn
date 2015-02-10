// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"os"
	"time"

	"github.com/apptimistco/asn/debug/accumulator"
)

type FH struct {
	// asn file header
	V    Version
	Id   Id
	Blob Blob
}

func NewFH(owner, author *PubEncr, name string) *FH {
	return &FH{
		V:  Latest,
		Id: BlobId,
		Blob: Blob{
			Owner:  *owner,
			Author: *author,
			Name:   name,
			Time:   time.Now(),
		},
	}
}

func (fh *FH) ReadFrom(r io.Reader) (n int64, err error) {
	var a accumulator.Int64
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
	}()
	a.Accumulate64(fh.V.ReadFrom(r))
	a.Accumulate64(fh.Id.ReadFrom(r))
	fh.Id = fh.Id.Version(fh.V)
	a.Accumulate64(fh.Blob.ReadFrom(r))
	return
}

func (fh *FH) WriteTo(w io.Writer) (n int64, err error) {
	var a accumulator.Int64
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
	}()
	a.Accumulate64(fh.V.WriteTo(w))
	a.Accumulate64(fh.Id.WriteTo(w))
	a.Accumulate64(fh.Blob.WriteTo(w))
	return
}

func ReadFileHeader(fn string) (fh *FH, err error) {
	f, err := os.Open(fn)
	defer f.Close()
	if err != nil {
		return
	}
	fh = new(FH)
	_, err = fh.ReadFrom(f)
	if err != nil {
		fh = nil
	}
	return
}
