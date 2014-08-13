// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mark

import (
	"github.com/apptimistco/asn/pdu/reflection"
	"github.com/apptimistco/encr"
	"testing"
)

func Test(t *testing.T) {
	key, _, _ := encr.NewRandomKeys()
	var lat, lon, ele float64 = 37.619002, -122.374843, 100

	pass := reflection.Check(NewMarkReq(lat, lon, ele, Checkin))
	pass = pass && reflection.Check(NewMarkRpt(lat, lon, ele, key))
	if !pass {
		t.Fail()
	}
}
