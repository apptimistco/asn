// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"crypto/rand"
	"github.com/apptimistco/asn"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/box"
	"github.com/apptimistco/encr"
)

func rekey(srv *server, ses *ses, req asn.Requester) {
	var nonce box.Nonce
	rand.Reader.Read(nonce[:])
	pub, sec, _ := encr.NewRandomKeys()
	ses.asn.Ack(req, pub[:], nonce[:])
	ses.asn.SetStateEstablished()
	ses.asn.SetBox(box.New(2, &nonce, &ses.peer, pub, sec))
	srv.log.Println("rekey", ses.asn.Name, pub.String())
}

func rxLogin(srv *server, ses *ses, pdu *asn.PDU) (err error) {
	var req asn.Requester
	var key encr.Pub
	var sig auth.Sig
	req.ReadFrom(pdu)
	_, err = pdu.Read(key[:])
	if err == nil {
		_, err = pdu.Read(sig[:])
	}
	if err != nil {
		return
	}
	if key.Equal(srv.config.Keys.Admin.Pub.Encr) {
		if sig.Verify(srv.config.Keys.Admin.Pub.Auth, key[:]) {
			ses.asn.Name = srv.config.Name + "[Admin]"
		} else {
			err = asn.ErrFailure
		}
	} else {
		// FIXME user lookup
		err = asn.ErrFailure
	}
	if err == nil {
		rekey(srv, ses, req)
		srv.log.Println("login", ses.asn.Name)
	} else {
		srv.log.Println("login", err)
	}
	return err
}

func rxPause(srv *server, ses *ses, pdu *asn.PDU) error {
	var req asn.Requester
	req.ReadFrom(pdu)
	ses.asn.Ack(req)
	ses.asn.SetStateSuspended()
	srv.log.Println("suspended", ses.asn.Name)
	return nil
}

func rxQuit(srv *server, ses *ses, pdu *asn.PDU) error {
	var req asn.Requester
	req.ReadFrom(pdu)
	ses.asn.Ack(req)
	ses.asn.SetStateQuitting()
	srv.log.Println("quitting", ses.asn.Name)
	return nil
}

func rxResume(srv *server, ses *ses, pdu *asn.PDU) error {
	var req asn.Requester
	req.ReadFrom(pdu)
	rekey(srv, ses, req)
	srv.log.Println("resuming", ses.asn.Name)
	return nil
}
