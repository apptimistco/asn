// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ack

import "github.com/apptimistco/asn/pdu"

type Ack struct {
	Req pdu.Id
	Err pdu.Err
}

func init() {
	pdu.Register(pdu.AckId, func() pdu.PDUer { return &Ack{} })
}

func NewAck(req pdu.Id, err pdu.Err) *Ack {
	return &Ack{Req: req, Err: err}
}

func (ack *Ack) Format(version uint8) []byte {
	return []byte{version, pdu.AckId.Version(version),
		ack.Req.Version(version), ack.Err.Version(version)}
}

func (ack *Ack) Parse(header []byte) pdu.Err {
	if l := len(header); l < 2 {
		ack.Req = pdu.UnknownId
		ack.Err = pdu.UnknownErr
	} else if l < 3 {
		ack.Req = pdu.NormId(header[0], header[2])
		ack.Err = pdu.UnknownErr
	} else {
		ack.Req = pdu.NormId(header[0], header[2])
		ack.Err = pdu.NormErr(header[0], header[3])
	}
	return pdu.Success
}

func (ack *Ack) String(_ []byte) string {
	return ack.Req.String() + " " + ack.Err.String()
}
