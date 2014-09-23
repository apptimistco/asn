// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import "io"

type ReadLener interface {
	io.Reader
	Len() int
}

type Sums []Sum

// Sums{}.ReadFrom *after* Name{}.ReadFrom
func (p *Sums) ReadFrom(rl ReadLener) (n int64, err error) {
	nsums := rl.Len() / SumSz
	*p = make(Sums, 0, nsums)
	for i := 0; i < nsums; i++ {
		var sum Sum
		ni, rerr := rl.Read(sum[:])
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
