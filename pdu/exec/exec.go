// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package exec

import (
	"github.com/apptimistco/asn/pdu"
	"strings"
)

type Exec []string

func init() {
	pdu.Register(pdu.ExecReqId, func() pdu.PDUer {
		return &Exec{}
	})
}

func NewExec(args ...string) *Exec {
	e := Exec(args)
	return &e
}

func (p *Exec) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.ExecReqId.Version(version)})
	h.Write([]byte(strings.Join(*p, "\x00")))
}

func (p *Exec) Id() pdu.Id { return pdu.ExecReqId }

func (p *Exec) Parse(h pdu.Header) pdu.Err {
	hlen := h.Len()
	if hlen <= 1+1+1 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	*p = strings.Split(string(h.Bytes()), "\x00")
	return pdu.Success
}

func (p *Exec) String() string {
	return strings.Join(*p, " ")
}
