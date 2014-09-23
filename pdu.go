// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"github.com/apptimistco/datum"
	"io"
)

// FIXME for now wrap datum but eventually replace it
type PDU datum.Datum

func FlushPDU() {
	datum.Flush()
}

func NewPDU() *PDU {
	Diag.Output(2, "pdu alloc")
	return (*PDU)(datum.Pull())
}

func (pdu *PDU) Free() {
	Diag.Output(2, "pdu free")
	if pdu != nil {
		d := (*datum.Datum)(pdu)
		datum.Push(&d)
	}
}

func (pdu *PDU) Len() int {
	return (*datum.Datum)(pdu).Len()
}

func (pdu *PDU) Limit(l int64) {
	(*datum.Datum)(pdu).Limit(l)
}

func (pdu *PDU) Read(b []byte) (int, error) {
	return (*datum.Datum)(pdu).Read(b)
}

func (pdu *PDU) ReadFrom(r io.Reader) (int64, error) {
	return (*datum.Datum)(pdu).ReadFrom(r)
}

func (pdu *PDU) Reset() {
	(*datum.Datum)(pdu).Reset()
}

func (pdu *PDU) Rewind() error {
	return (*datum.Datum)(pdu).Rewind()
}

func (pdu *PDU) Write(b []byte) (int, error) {
	return (*datum.Datum)(pdu).Write(b)
}

func (pdu *PDU) WriteTo(w io.Writer) (int64, error) {
	return (*datum.Datum)(pdu).WriteTo(w)
}
