// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"github.com/apptimistco/asn/pdu"
	"os"
)

var out = os.Stdout

func Example() {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.NpduIds)

	sname := "File"
	fname := "foo/bar"
	data := []byte("the quick brown fox")

	aLockReq := NewLockReq(fname)
	bLockReq := pdu.New(pdu.FileLockReqId)
	bLockReq.Parse(aLockReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.FileLockReqId, bLockReq, data)

	aReadReq := NewReadReq(fname)
	bReadReq := pdu.New(pdu.FileReadReqId)
	bReadReq.Parse(aReadReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.FileReadReqId, bReadReq, data)

	aRemoveReq := NewRemoveReq(fname)
	bRemoveReq := pdu.New(pdu.FileRemoveReqId)
	bRemoveReq.Parse(aRemoveReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.FileRemoveReqId, bRemoveReq, data)

	aWriteReq := NewWriteReq(fname)
	bWriteReq := pdu.New(pdu.FileWriteReqId)
	bWriteReq.Parse(aWriteReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.FileWriteReqId, bWriteReq, data)

	// Output:
}
