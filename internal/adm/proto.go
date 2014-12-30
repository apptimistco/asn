// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package adm

import (
	"strings"

	"github.com/apptimistco/asn/internal/asn"
)

func (adm *Adm) Exec(args ...string) (err error) {
	var pdu *asn.PDU
	for _, arg := range args {
		if arg == "-" {
			f, terr := adm.asn.Repos.Tmp.NewFile()
			if terr != nil {
				err = terr
				return
			}
			pdu = asn.NewPDUFile(f)
			f = nil
			break
		}
	}
	if pdu == nil {
		pdu = asn.NewPDUBuf()
	}
	v := adm.asn.Version()
	v.WriteTo(pdu)
	asn.ExecReqId.Version(v).WriteTo(pdu)
	req := asn.NewRequesterString("exec")
	req.WriteTo(pdu)
	pdu.Write([]byte(strings.Join(args, "\x00")))
	for _, arg := range args {
		if arg == "-" {
			pdu.Write([]byte{0, 0}[:])
			pdu.ReadFrom(Stdin)
			break
		}
	}
	adm.asn.Diag(asn.ExecReqId, strings.Join(args, " "))
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req asn.Requester, ack *asn.PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.asn.Diag("ack")
			ack.WriteTo(Stdout)
		} else {
			adm.asn.Diag("nack", err)
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(pdu)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) Login() (err error) {
	login := asn.NewPDUBuf()
	key := adm.config.Keys.Admin.Pub.Encr
	sig := adm.config.Keys.Admin.Sec.Auth.Sign(key[:])
	v := adm.asn.Version()
	v.WriteTo(login)
	asn.LoginReqId.Version(v).WriteTo(login)
	req := asn.NewRequesterString("login")
	req.WriteTo(login)
	login.Write(key[:])
	login.Write(sig[:])
	adm.asn.Diag(asn.LoginReqId, key.String()[:8]+"...",
		sig.String()[:8]+"...")
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req asn.Requester, ack *asn.PDU) error {
		adm.asn.Diag("rx ack of", req)
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.asn.Diag("login rekey")
			adm.rekey(ack)
		} else {
			adm.asn.Diag("login", err)
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(login)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) Pause() (err error) {
	pause := asn.NewPDUBuf()
	v := adm.asn.Version()
	v.WriteTo(pause)
	asn.PauseReqId.Version(v).WriteTo(pause)
	req := asn.NewRequesterString("pause")
	req.WriteTo(pause)
	adm.asn.Diag(asn.PauseReqId)
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req asn.Requester, ack *asn.PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.asn.SetStateSuspended()
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(pause)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) rekey(pdu *asn.PDU) {
	var peer asn.EncrPub
	var nonce asn.Nonce
	pdu.Read(peer[:])
	pdu.Read(nonce[:])
	adm.asn.Diag("new key:", peer)
	adm.asn.Diag("new nonce:", nonce)
	adm.asn.SetBox(asn.NewBox(2, &nonce, &peer,
		adm.ephemeral.pub, adm.ephemeral.sec))
	adm.asn.SetStateEstablished()
}

func (adm *Adm) Resume() (err error) {
	resume := asn.NewPDUBuf()
	v := adm.asn.Version()
	v.WriteTo(resume)
	asn.ResumeReqId.Version(v).WriteTo(resume)
	req := asn.NewRequesterString("resume")
	req.WriteTo(resume)
	adm.asn.Diag(asn.ResumeReqId)
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req asn.Requester, ack *asn.PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		if err == nil {
			adm.rekey(ack)
		}
		ackCh <- err
		return nil
	})
	adm.asn.Tx(resume)
	err = <-ackCh
	close(ackCh)
	return
}

func (adm *Adm) Quit() (err error) {
	quit := asn.NewPDUBuf()
	v := adm.asn.Version()
	v.WriteTo(quit)
	asn.QuitReqId.Version(v).WriteTo(quit)
	req := asn.NewRequesterString("quit")
	req.WriteTo(quit)
	adm.asn.Diag(asn.QuitReqId)
	adm.asn.SetStateQuitting()
	ackCh := make(chan error, 1)
	adm.asn.Acker.Map(req, func(req asn.Requester, ack *asn.PDU) error {
		adm.asn.Acker.UnMap(req)
		err := adm.asn.ParseAckError(ack)
		ackCh <- err
		return nil
	})
	adm.asn.Tx(quit)
	err = <-ackCh
	close(ackCh)
	return
}
