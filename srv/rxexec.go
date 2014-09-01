// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/pdu/exec"
	"github.com/apptimistco/datum"
	"strings"
)

const execHelp = `ASN exec commands
echo [ARGS...]
	Returns space separated ARGS in the Ack data.
`

func rxExec(srv *server, ses *ses, vpdu pdu.PDUer, d *datum.Datum) error {
	p, ok := vpdu.(*exec.Exec)
	if !ok {
		return pdu.ErrParse
	}
	args := []string(*p)
	if len(args) <= 0 {
		return pdu.ErrIlFormat
	}
	switch args[0] {
	case "help":
		datum.Push(&d)
		ses.asn.Ack(p.Id(), pdu.Success, execHelp)
	case "echo":
		datum.Push(&d)
		reply := ""
		if len(args) > 1 {
			reply = strings.Join(args[1:], " ")
		}
		ses.asn.Ack(p.Id(), pdu.Success, reply)
	case "trace":
		datum.Push(&d)
		execTrace(srv, ses, args[1:]...)
	default:
		datum.Push(&d)
		ses.asn.Ack(p.Id(), pdu.UnknownErr, nil)
	}
	return nil
}

func execTrace(srv *server, ses *ses, args ...string) {
	if len(args) == 0 || args[0] == "flush" {
		d := datum.Pull()
		pdu.TraceFlush(d)
		ses.asn.Ack(pdu.ExecReqId, pdu.Success, d)
		return
	}
	// FIXME
	switch args[1] {
	case "filter":
		ses.asn.Ack(pdu.ExecReqId, pdu.FailureErr, nil)
	case "unfilter":
		ses.asn.Ack(pdu.ExecReqId, pdu.FailureErr, nil)
	case "resize":
		ses.asn.Ack(pdu.ExecReqId, pdu.FailureErr, nil)
	}
}
