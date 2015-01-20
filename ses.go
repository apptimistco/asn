// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/rand"
	"os"
	"strings"
	"syscall"
)

type Ses struct {
	name string
	ASN  *ASN
	srv  *Server
	Keys struct {
		Server struct {
			Ephemeral EncrPub
		}
		Client struct {
			Ephemeral, Login EncrPub
		}
	}

	Lat, Lon, Range int32

	asnsrv bool // true if: asnsrv CONFIG ...
}

var SesPool chan *Ses

func init() { SesPool = make(chan *Ses, 16) }

func NewSes() (ses *Ses) {
	select {
	case ses = <-SesPool:
	default:
		ses = &Ses{}
	}
	ses.ASN = NewASN()
	return
}

func SesPoolFlush() {
	for {
		select {
		case <-SesPool:
		default:
			return
		}
	}
}

func (ses *Ses) DN() string { return ses.srv.cmd.Cfg.Dir }

// dist pdu list to online sessions. Any sessions to other servers receive the
// first link which is the RESPO/SHA. All user sessions receive "asn/mark". Any
// other named blob named REPOS/USER/PATH goes to the associated USER sessions.
func (ses *Ses) dist(pdus []*PDU) {
	ses.srv.ForEachSession(func(x *Ses) {
		if x == ses {
			return
		}
		login := x.Keys.Client.Login
		slogin := login.String()
		server := x.srv.cmd.Cfg.Keys.Server.Pub.Encr
		if login.Equal(server) {
			if pdus[0] != nil {
				x.ASN.Tx(pdus[0])
			}
			return
		}
		for _, pdu := range pdus[1:] {
			if pdu != nil {
				suser, _ := x.srv.repos.ParsePath(pdu.FN)
				if suser != "" &&
					suser == slogin[:len(suser)] {
					x.ASN.Tx(pdu)
					// be sure to send only one per session
					return
				}
			}
		}
	})
	for i := range pdus {
		pdus[i].Free()
		pdus[i] = nil
	}
}

// Free the Ses by pooling or release it to GC if pool is full.
func (ses *Ses) Free() {
	if ses != nil {
		ses.name = ""
		ses.ASN.Free()
		ses.ASN = nil
		ses.srv = nil
		select {
		case SesPool <- ses:
		default:
		}
	}
}

func (ses *Ses) IsAdmin(key *EncrPub) bool {
	return *key == *ses.srv.cmd.Cfg.Keys.Admin.Pub.Encr
}

func (ses *Ses) IsService(key *EncrPub) bool {
	return *key == *ses.srv.cmd.Cfg.Keys.Server.Pub.Encr
}

func (ses *Ses) Rekey(req Requester) {
	var nonce Nonce
	rand.Reader.Read(nonce[:])
	pub, sec, _ := NewRandomEncrKeys()
	ses.Keys.Server.Ephemeral = *pub
	ses.ASN.Ack(req, pub[:], nonce[:])
	ses.ASN.SetStateEstablished()
	ses.ASN.SetBox(NewBox(2, &nonce, &ses.Keys.Client.Ephemeral,
		pub, sec))
	ses.ASN.Println("rekeyed with", pub.String()[:8]+"...")
}

// removals: if pdus[1] is a filename containing "asn/removals",
// remove the referenced files, then the "asn/removals/" link.
// However, keep the SUM file to distribute with clone.
func (ses *Ses) removals(pdus []*PDU) {
	if len(pdus) == 2 && pdus[1] != nil &&
		strings.Contains(pdus[1].FN, "asn/removals") {
		f, err := os.Open(pdus[1].FN)
		if err != nil {
			return
		}
		defer func() {
			f.Close()
			syscall.Unlink(pdus[1].FN)
			pdus[1].Free()
			pdus[1] = nil
		}()
		BlobSeek(f)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fn := ses.srv.repos.Join(scanner.Text())
			ses.ASN.Diag("unlinked", fn)
			syscall.Unlink(fn)
		}
		scanner = nil
	}
}

func (ses *Ses) RxBlob(pdu *PDU) (err error) {
	blob, err := NewBlobFrom(pdu)
	if err != nil {
		return
	}
	defer func() {
		blob.Free()
		blob = nil
	}()
	sum, fn, err := ses.srv.repos.File(blob, pdu)
	if err != nil {
		return
	}
	links, err := ses.srv.repos.MkLinks(blob, sum, fn)
	if err != nil {
		return
	}
	ses.removals(links)
	ses.dist(links)
	links = nil
	return
}

func (ses *Ses) RxLogin(pdu *PDU) (err error) {
	var (
		req Requester
		sig AuthSig
	)
	req.ReadFrom(pdu)
	_, err = pdu.Read(ses.Keys.Client.Login[:])
	if err == nil {
		_, err = pdu.Read(sig[:])
	}
	if err != nil {
		return
	}
	err = ErrFailure
	switch {
	case ses.Keys.Client.Login.Equal(ses.srv.cmd.Cfg.Keys.Admin.Pub.Encr):
		if sig.Verify(ses.srv.cmd.Cfg.Keys.Admin.Pub.Auth,
			ses.Keys.Client.Login[:]) {
			ses.ASN.Name.Remote = "admin"
			err = nil
		}
	case ses.Keys.Client.Login.Equal(ses.srv.cmd.Cfg.Keys.Server.Pub.Encr):
		if sig.Verify(ses.srv.cmd.Cfg.Keys.Server.Pub.Auth,
			ses.Keys.Client.Login[:]) {
			ses.ASN.Name.Remote = "server"
			err = nil
		}
	default:
		login := ses.Keys.Client.Login
		user := ses.srv.repos.Users.Search(login)
		if user != nil && sig.Verify(&user.ASN.Auth, login[:]) {
			ses.ASN.Name.Remote = login.String()[:8]
			err = nil
		}
	}
	ses.ASN.Name.Session = ses.ASN.Name.Local + ":" + ses.ASN.Name.Remote
	if err != nil {
		ses.ASN.Println("login", err)
	} else {
		ses.Rekey(req)
		ses.ASN.Println("login")
	}
	return
}

func (ses *Ses) RxPause(pdu *PDU) error {
	var req Requester
	req.ReadFrom(pdu)
	ses.ASN.Println("suspending")
	ses.ASN.Ack(req)
	ses.ASN.SetStateSuspended()
	return nil
}

func (ses *Ses) RxQuit(pdu *PDU) error {
	var req Requester
	req.ReadFrom(pdu)
	ses.ASN.Println("quitting")
	ses.ASN.Ack(req)
	ses.ASN.SetStateQuitting()
	return nil
}

func (ses *Ses) RxResume(pdu *PDU) error {
	var req Requester
	req.ReadFrom(pdu)
	ses.ASN.Println("resuming")
	ses.Rekey(req)
	return nil
}

func (ses *Ses) Send(fn string, keys ...*EncrPub) {
	// FIXME
}
