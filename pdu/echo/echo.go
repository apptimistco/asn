// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package echo

import "github.com/apptimistco/asn/pdu"

const (
	Request uint8 = iota
	Reply
)

type Echo struct{ Reply uint8 }

func init() {
	pdu.Register(pdu.EchoId, func() pdu.PDUer {
		return &Echo{}
	})
}

func NewEcho(reply uint8) *Echo { return &Echo{Reply: reply} }

func (echo *Echo) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.EchoId.Version(version), echo.Reply})
}

func (echo *Echo) Id() pdu.Id { return pdu.EchoId }

func (echo *Echo) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+1 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	echo.Reply = pdu.Getc(h)
	return pdu.Success
}

func (echo *Echo) String() string {
	if echo.Reply == Reply {
		return "Reply"
	}
	return "Request"
}
