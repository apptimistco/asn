// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package echo

import (
	"github.com/apptimistco/asn/pdu"
	"os"
)

var out = os.Stdout // use this writer for Examples with unspecified Output

func Example() {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.NpduIds)

	sname := "echo"
	b := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	aEcho := NewEcho(Request)
	pdu.Trace(sname, "Rx", pdu.EchoId, aEcho, b)
	aEcho.Reply = Reply
	pdu.Trace(sname, "Tx", pdu.EchoId, aEcho, b)
	bEcho := pdu.New(pdu.EchoId)
	pdu.Trace(sname, "Rx", pdu.EchoId, bEcho, b)

	// Output:
}
