// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"os"
)

type Sums []Sum

// fromBlob from named file.
// fromBlob will panic on error so the calling function must recover.
func (sums *Sums) fromBlob(fn string) {
	f, err := os.Open(fn)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		panic(err)
	}
	defer f.Close()
	pos := blobSeek(f)
	fi, err := f.Stat()
	if err != nil {
		panic(err)
	}
	n := int(fi.Size()-pos) / SumSz
	*sums = Sums(make([]Sum, n))
	for i := 0; i < n; i++ {
		f.Read([]Sum(*sums)[i][:])
	}
}

// Sums{}.ReadFrom *after* Name{}.ReadFrom
func (p *Sums) ReadFrom(r LenReader) (n int64, err error) {
	nsums := r.Len() / SumSz
	*p = make(Sums, 0, nsums)
	for i := 0; i < nsums; i++ {
		var sum Sum
		ni, rerr := r.Read(sum[:])
		if rerr != nil {
			err = rerr
			return
		}
		n += int64(ni)
		*p = append(*p, sum)
	}
	return
}

// Sums{}.WriteTo *after* Name{}.WriteTo
func (p *Sums) WriteTo(w io.Writer) (n int64, err error) {
	for _, sum := range *p {
		ni, werr := w.Write(sum[:])
		if werr != nil {
			err = werr
			break
		}
		n += int64(ni)
	}
	return
}
