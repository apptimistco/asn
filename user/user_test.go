// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package user

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/encr"
	"os"
)

var out = os.Stdout

func Example() {
	defer pdu.TraceFlush(out)
	pdu.TraceUnfilter(pdu.NpduIds)

	sname := "user"
	pubEncr, _, _ := encr.NewRandomKeys()
	pubAuth, secAuth, _ := auth.NewRandomKeys()
	sig := secAuth.Sign(pubEncr[:])
	name := "jane doe"
	fbuid := "jane.doe@facebook.com"
	fbtoken := "123"
	data := []byte{}

	aAddReq := NewAddReq(Actual, name, fbuid, fbtoken, pubEncr, pubAuth)
	bAddReq := pdu.New(pdu.UserAddReqId)
	bAddReq.Parse(aAddReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.UserAddReqId, bAddReq, data)

	aDelReq := NewDelReq(pubEncr)
	bDelReq := pdu.New(pdu.UserDelReqId)
	bDelReq.Parse(aDelReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.UserDelReqId, bDelReq, data)

	aSearchReq := NewSearchReq(SearchByName, "j.*doe")
	bSearchReq := pdu.New(pdu.UserSearchReqId)
	bSearchReq.Parse(aSearchReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.UserSearchReqId, bSearchReq, data)

	aVouchReq := NewVouchReq(pubEncr, sig, false)
	bVouchReq := pdu.New(pdu.UserVouchReqId)
	bVouchReq.Parse(aVouchReq.Format(pdu.Version))
	pdu.Trace(sname, "Tx", pdu.UserVouchReqId, bVouchReq, data)
	aVouchReq.Revoke = true
	pdu.Trace(sname, "Tx", pdu.UserVouchReqId, aVouchReq, data)

	// Output:
}
