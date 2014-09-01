// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package exec

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/tgrennan/quotation"
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

func (p *Exec) bytes() []uint8 {
	b := make([]uint8, 0, 4096)
	for i, s := range *p {
		if i > 0 {
			b = append(b, ' ')
		}
		if strings.ContainsAny(s, " \t\n") {
			b = append(b, '"')
			b = append(b, s...)
			b = append(b, '"')
		} else {
			b = append(b, s...)
		}
	}
	return b
}

func (p *Exec) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.ExecReqId.Version(version)})
	b := p.bytes()
	h.Write(b)
	b = nil
}

func (p *Exec) Id() pdu.Id { return pdu.ExecReqId }

func (p *Exec) Parse(h pdu.Header) pdu.Err {
	hlen := h.Len()
	if hlen <= 1+1+1 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	*p = quotation.Fields(string(h.Bytes()))
	return pdu.Success
}

func (p *Exec) String() string {
	return string(p.bytes())
}
