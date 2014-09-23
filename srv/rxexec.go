// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"bytes"
	"github.com/apptimistco/asn"
	"strings"
)

const execHelp = `ASN exec commands
echo [ARGS...]
	Returns space separated ARGS in the Ack data.
`

func rxExec(srv *server, ses *ses, pdu *asn.PDU) error {
	var req asn.Requester
	var cmd [256]byte
	const sep = "--\x00"
	req.ReadFrom(pdu)
	n, _ := pdu.Read(cmd[:])
	sepi := bytes.Index(cmd[:n], []byte(sep))
	if sepi > 0 {
		n = sepi
	}
	args := strings.Split(string(cmd[:n]), "\x00")
	if sepi > 0 {
		pdu.Rewind()
		pdu.Read(cmd[:sepi+len(sep)])
	}
	switch args[0] {
	case "help":
		ses.asn.Ack(req, execHelp)
	case "echo":
		ses.asn.Ack(req, strings.Join(args[1:], " "))
	case "get":
		srv.log.Println("FIXME", args[0])
		ses.asn.Ack(req, asn.ErrUnknown)
	case "trace":
		execTrace(srv, ses, req, args[1:]...)
	case "put":
		srv.log.Println("FIXME", args[0])
		ses.asn.Ack(req, asn.ErrUnknown)
	default:
		srv.log.Println(asn.ErrUnknown, args[0])
		ses.asn.Ack(req, asn.ErrUnknown)
	}
	return nil
}

func execTrace(srv *server, ses *ses, req asn.Requester, args ...string) {
	if len(args) == 0 {
		args = append(args, "flush")
	}
	switch args[0] {
	case "flush":
		ses.asn.Ack(req, asn.TraceFlush)
	case "filter", "unfilter", "resize":
		srv.log.Println("FIXME", "trace", args[0])
		ses.asn.Ack(req, asn.ErrUnknown)
	}
}
