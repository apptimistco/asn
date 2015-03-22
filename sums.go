// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "io"

type Sums []Sum

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
func (sums Sums) WriteTo(w io.Writer) (n int64, err error) {
	for _, sum := range sums {
		ni, werr := w.Write(sum[:])
		if werr != nil {
			err = werr
			break
		}
		n += int64(ni)
	}
	return
}
