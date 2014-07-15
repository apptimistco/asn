// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

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

	sname := "session"
	pubEncr, _, _ := encr.NewRandomKeys()
	_, secAuth, _ := auth.NewRandomKeys()
	sig := secAuth.Sign(pubEncr[:])
	url := "ws://siren.apptimist.co/ws/asn/loc?key=" + pubEncr.String()
	data := []byte{}

	aLoginReq := NewLoginReq(pubEncr, sig)
	bLoginReq := pdu.New(pdu.SessionLoginReqId)
	bLoginReq.Parse(aLoginReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.SessionLoginReqId, bLoginReq, data)

	aPauseReq := NewPauseReq()
	bPauseReq := pdu.New(pdu.SessionPauseReqId)
	bPauseReq.Parse(aPauseReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.SessionPauseReqId, bPauseReq, data)

	aRedirectReq := NewRedirectReq(url)
	bRedirectReq := pdu.New(pdu.SessionRedirectReqId)
	bRedirectReq.Parse(aRedirectReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.SessionRedirectReqId, bRedirectReq, data)

	aResumeReq := NewResumeReq()
	bResumeReq := pdu.New(pdu.SessionResumeReqId)
	bResumeReq.Parse(aResumeReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.SessionResumeReqId, bResumeReq, data)

	aQuitReq := NewQuitReq()
	bQuitReq := pdu.New(pdu.SessionQuitReqId)
	bQuitReq.Parse(aQuitReq.Format(pdu.Version))
	pdu.Trace(sname, "Rx", pdu.SessionQuitReqId, bQuitReq, data)

	// Output:
}
