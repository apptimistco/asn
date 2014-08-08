// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package message

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/encr"
	"os"
)

var out = os.Stdout

func Example() {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.NpduIds)

	sname := "message"
	to, _, _ := encr.NewRandomKeys()
	from, _, _ := encr.NewRandomKeys()
	data := []byte{}
	var head Id

	aMessageReq := NewMessageReq(to, from)
	bMessageReq := pdu.New(pdu.MessageReqId)
	bMessageReq.Parse(aMessageReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.MessageReqId, bMessageReq, data)

	aHeadRpt := NewHeadRpt(to, &head)
	bHeadRpt := pdu.New(pdu.HeadRptId)
	bHeadRpt.Parse(aHeadRpt.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.HeadRptId, bHeadRpt, data)

	// Output:
}
