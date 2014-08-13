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

func (ack *Ack) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.AckId.Version(version),
		ack.Req.Version(version), ack.Err.Version(version)})
}

func (ack *Ack) Id() pdu.Id { return pdu.AckId }

func (ack *Ack) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+1+1 {
		return pdu.IlFormatErr
	}
	version := pdu.Getc(h)
	_ = pdu.Getc(h)
	ack.Req = pdu.NormId(version, pdu.Getc(h))
	ack.Err = pdu.NormErr(version, pdu.Getc(h))
	return pdu.Success
}

func (ack *Ack) String() string {
	return ack.Req.String() + " " + ack.Err.String()
}
