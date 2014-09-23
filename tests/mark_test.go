// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"bytes"
	"github.com/apptimistco/asn"
	"testing"
)

func TestMark(t *testing.T) {
	if !asn.MarkName.Equal(asn.MarkString) {
		t.Error("MarkName:", asn.MarkName, "vs.", asn.MarkString)
	}
	const (
		lat = float64(37.619002)
		lon = float64(-122.374843)
		ele = float64(100)
	)
	b := &bytes.Buffer{}
	(&asn.Mark{Lat: lat, Lon: lon, Ele: ele}).WriteTo(b)
	var m asn.Mark
	m.ReadFrom(b)
	if m.Lat != lat {
		t.Error("Mismatch", m.Lat, "vs.", lat)
	}
	if m.Lon != lon {
		t.Error("Mismatch", m.Lon, "vs.", lon)
	}
	if m.Ele != ele {
		t.Errorf("Mismatch", m.Ele, "vs.", ele)
	}
}
