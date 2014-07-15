// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package echo

import (
	"encoding/hex"
	"github.com/apptimistco/asn/pdu"
)

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

func (echo *Echo) Format(version uint8) []byte {
	return []byte{version, pdu.EchoId.Version(version), echo.Reply}
}

func (echo *Echo) Parse(header []byte) pdu.Err {
	if len(header) != 1+1+1 {
		return pdu.IlFormatErr
	}
	echo.Reply = header[2]
	return pdu.Success
}

func (echo *Echo) String(data []byte) string {
	s := hex.EncodeToString(data)
	if echo.Reply == Reply {
		return "Reply " + s
	}
	return "Request " + s
}
