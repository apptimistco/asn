// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package srv

import (
	"bufio"
	"crypto/rand"
	"github.com/apptimistco/asn"
	"os"
	"strings"
	"syscall"
)

type Ses struct {
	name string
	ASN  *asn.ASN
	srv  *Server
	Keys struct {
		Server struct {
			Ephemeral asn.EncrPub
		}
		Client struct {
			Ephemeral, Login asn.EncrPub
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
	ses.ASN = asn.NewASN()
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

func (ses *Ses) DN() string { return ses.srv.Config.Dir }

// dist pdu list to online sessions. Any sessions to other servers receive the
// first link which is the RESPO/SHA. All user sessions receive "asn/mark". Any
// other named blob named REPOS/USER/PATH goes to the associated USER sessions.
func (ses *Ses) dist(pdus []*asn.PDU) {
	ses.srv.ForEachSession(func(x *Ses) {
		if x == ses {
			return
		}
		login := x.Keys.Client.Login
		slogin := login.String()
		server := x.srv.Config.Keys.Server.Pub.Encr
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
		ses.ASN.Free()
		ses.ASN = nil
		ses.srv = nil
		select {
		case SesPool <- ses:
		default:
		}
	}
}

func (ses *Ses) IsAdmin(key *asn.EncrPub) bool {
	return *key == *ses.srv.Config.Keys.Admin.Pub.Encr
}

func (ses *Ses) IsService(key *asn.EncrPub) bool {
	return *key == *ses.srv.Config.Keys.Server.Pub.Encr
}

func (ses *Ses) Rekey(req asn.Requester) {
	var nonce asn.Nonce
	rand.Reader.Read(nonce[:])
	pub, sec, _ := asn.NewRandomEncrKeys()
	ses.Keys.Server.Ephemeral = *pub
	ses.ASN.Ack(req, pub[:], nonce[:])
	ses.ASN.SetStateEstablished()
	ses.ASN.SetBox(asn.NewBox(2, &nonce, &ses.Keys.Client.Ephemeral,
		pub, sec))
	ses.ASN.Println("rekeyed with", pub.String()[:8]+"...")
}

// removals: if pdus[1] is a filename containing "asn/removals",
// remove the referenced files, then the "asn/removals/" link.
// However, keep the SUM file to distribute with clone.
func (ses *Ses) removals(pdus []*asn.PDU) {
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
		asn.BlobSeek(f)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fn := ses.srv.repos.Join(scanner.Text())
			asn.Diag.Println("unlinked", fn)
			syscall.Unlink(fn)
		}
		scanner = nil
	}
}

func (ses *Ses) RxBlob(pdu *asn.PDU) (err error) {
	blob, err := asn.NewBlobFrom(pdu)
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

func (ses *Ses) RxLogin(pdu *asn.PDU) (err error) {
	var (
		req asn.Requester
		sig asn.AuthSig
	)
	req.ReadFrom(pdu)
	_, err = pdu.Read(ses.Keys.Client.Login[:])
	if err == nil {
		_, err = pdu.Read(sig[:])
	}
	if err != nil {
		return
	}
	err = asn.ErrFailure
	switch {
	case ses.Keys.Client.Login.Equal(ses.srv.Config.Keys.Admin.Pub.Encr):
		if sig.Verify(ses.srv.Config.Keys.Admin.Pub.Auth,
			ses.Keys.Client.Login[:]) {
			ses.ASN.Name = ses.srv.Config.Name + "[Admin]"
			err = nil
		}
	case ses.Keys.Client.Login.Equal(ses.srv.Config.Keys.Server.Pub.Encr):
		if sig.Verify(ses.srv.Config.Keys.Server.Pub.Auth,
			ses.Keys.Client.Login[:]) {
			ses.ASN.Name = ses.srv.Config.Name + "[Server]"
			err = nil
		}
	default:
		user := ses.srv.repos.Users.Search(ses.Keys.Client.Login.String())
		if user != nil &&
			sig.Verify(&user.ASN.Auth, ses.Keys.Client.Login[:]) {
			ses.ASN.Name = ses.srv.Config.Name + "[" +
				ses.Keys.Client.Login.String()[:8] + "]"
			err = nil
		}
	}
	if err != nil {
		ses.ASN.Println("login", err)
	} else {
		ses.Rekey(req)
		ses.ASN.Println("login")
	}
	return
}

func (ses *Ses) RxPause(pdu *asn.PDU) error {
	var req asn.Requester
	req.ReadFrom(pdu)
	ses.ASN.Println("suspending")
	ses.ASN.Ack(req)
	ses.ASN.SetStateSuspended()
	return nil
}

func (ses *Ses) RxQuit(pdu *asn.PDU) error {
	var req asn.Requester
	req.ReadFrom(pdu)
	ses.ASN.Println("quitting")
	ses.ASN.Ack(req)
	ses.ASN.SetStateQuitting()
	return nil
}

func (ses *Ses) RxResume(pdu *asn.PDU) error {
	var req asn.Requester
	req.ReadFrom(pdu)
	ses.ASN.Println("resuming")
	ses.Rekey(req)
	return nil
}

func (ses *Ses) Send(fn string, keys ...*asn.EncrPub) {
	// FIXME
}
