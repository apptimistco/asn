// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"github.com/apptimistco/nbo"
	"io"
)

const MarkString = "asn/mark"

var MarkName = Name(MarkString)

type Mark struct {
	Lat, Lon, Ele float64
}

// Mark{}.ReadFrom *after* Name{}.ReadFrom
func (m *Mark) ReadFrom(r io.Reader) (n int64, err error) {
	for _, pf := range []*float64{&m.Lat, &m.Lon, &m.Ele} {
		var ni int
		ni, err = (nbo.Reader{r}).ReadNBO(pf)
		if err != nil {
			return
		}
		n += int64(ni)
	}
	return
}

// Mark{}.WriteTo *after* MarkName.WriteTo
func (m *Mark) WriteTo(w io.Writer) (n int64, err error) {
	for _, f := range []float64{m.Lat, m.Lon, m.Ele} {
		var ni int
		ni, err = (nbo.Writer{w}).WriteNBO(f)
		if err != nil {
			return
		}
		n += int64(ni)
	}
	return
}
