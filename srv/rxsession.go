// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/pdu/session"
	"github.com/apptimistco/datum"
)

func rxLogin(srv *server, ses *ses, vpdu pdu.PDUer, d *datum.Datum) error {
	req, ok := vpdu.(*session.LoginReq)
	if !ok {
		return pdu.ErrParse
	}
	if req.Key.Equal(srv.config.Keys.Admin.Pub.Encr) {
		if req.Sig.Verify(srv.config.Keys.Admin.Pub.Auth, req.Key[:]) {
			ses.asn.Name = srv.config.Name + "[Admin]"
			ses.asn.Ack(req.Id(), pdu.Success, nil)
		} else {
			ses.asn.Ack(req.Id(), pdu.FailureErr, nil)
		}
	} else {
		// FIXME user lookup
		ses.asn.Ack(req.Id(), pdu.FailureErr, nil)
	}
	return nil
}
