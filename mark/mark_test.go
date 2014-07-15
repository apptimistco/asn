// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mark

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/encr"
	"os"
)

var out = os.Stdout

func Example() {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.NpduIds)

	sname := "location"
	key, _, _ := encr.NewRandomKeys()
	data := []byte{}
	var lat, lon, ele float64 = 37.619002, -122.374843, 100

	aMarkReq := NewMarkReq(lat, lon, ele, Set)
	bMarkReq := pdu.New(pdu.MarkReqId)
	bMarkReq.Parse(aMarkReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.MarkReqId, bMarkReq, data)

	aMarkRpt := NewMarkRpt(key, lat, lon, ele)
	bMarkRpt := pdu.New(pdu.MarkRptId)
	bMarkRpt.Parse(aMarkRpt.Format(pdu.Version))
	pdu.Trace(sname, "Tx", pdu.MarkRptId, bMarkRpt, data)

	// Output:
}
