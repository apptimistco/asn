// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ack

import (
	"github.com/apptimistco/asn/pdu"
	"os"
)

var out = os.Stdout

func Example() {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.NpduIds)

	sname := "ack"
	data := []byte{}

	aAck := NewAck(pdu.SessionLoginReqId, pdu.Success)
	bAck := pdu.New(pdu.AckId)
	bAck.Parse(aAck.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.AckId, bAck, data)

	// Output:
}
