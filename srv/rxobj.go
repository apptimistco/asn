// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"github.com/apptimistco/asn"
	"io"
)

func ReadMagicObjNameFrom(r io.Reader) (obj asn.Obj, name asn.Name, err error) {
	if _, err = asn.ReadMagicFrom(r); err != nil {
		return
	}
	if _, err = obj.ReadFrom(r); err != nil {
		return
	}
	_, err = name.ReadFrom(r)
	return
}

func rxBlob(srv *server, ses *ses, pdu *asn.PDU) (err error) {
	obj, name, err := ReadMagicObjNameFrom(pdu)
	if err != nil {
		return
	}
	if name == asn.MarkName {
		var mark asn.Mark
		if _, err = mark.ReadFrom(pdu); err != nil {
			return
		}
	}
	// FIXME
	_ = obj
	_ = name
	return
}

func rxIndex(srv *server, ses *ses, pdu *asn.PDU) (err error) {
	obj, name, err := ReadMagicObjNameFrom(pdu)
	if err != nil {
		return
	}
	var sums asn.Sums
	if _, err = sums.ReadFrom(pdu); err != nil {
		return
	}
	// FIXME
	_ = obj
	_ = name
	sums = sums[:0]
	sums = nil
	return
}
