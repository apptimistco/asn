// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/pdu/ack"
	"github.com/apptimistco/datum"
)

type rxer func(*server, *ses, pdu.PDUer, *datum.Datum) error

var (
	rxers = [pdu.NpduIds]rxer{
		pdu.AckId:             rxAck,
		pdu.ExecReqId:         rxExec,
		pdu.SessionLoginReqId: rxLogin,
	}
)

func rxAck(srv *server, _ *ses, vpdu pdu.PDUer, d *datum.Datum) error {
	xack, ok := vpdu.(*ack.Ack)
	if !ok {
		return pdu.ErrParse
	}
	if xack.Err != pdu.Success {
		srv.log.Println(xack.Id(), xack.Req, "error", d)
	}
	return nil
}
