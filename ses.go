// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"time"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/file"
	"github.com/apptimistco/asn/debug/mutex"
)

type Ses struct {
	mutex.Mutex
	name string // remote name
	asn  asn
	cfg  *Config
	user *User
	Keys struct {
		Server struct {
			Ephemeral PubEncr
		}
		Client struct {
			Ephemeral, Login PubEncr
		}
	}

	ForEachLogin func(func(*Ses))

	asnsrv bool // true if server command line exec
}

func (ses *Ses) DN() string { return ses.cfg.Dir }

func (ses *Ses) IsAdmin(key *PubEncr) bool {
	return *key == *ses.cfg.Keys.Admin.Pub.Encr
}

func (ses *Ses) IsService(key *PubEncr) bool {
	return *key == *ses.cfg.Keys.Server.Pub.Encr
}

func (ses *Ses) Rekey(_ Req) {
	// FIXME
}

func (ses *Ses) Reset() {
	ses.name = ""
	ses.asn.Reset()
	ses.user = nil
	ses.cfg = nil
	ses.ForEachLogin = func(_ func(*Ses)) {}
}

func (ses *Ses) RxLogin(pdu *PDU) (err error) {
	var (
		req Req
		sig Signature
	)
	req.ReadFrom(pdu)
	_, err = pdu.Read(ses.Keys.Client.Login[:])
	if err == nil {
		_, err = pdu.Read(sig[:])
	}
	if err != nil {
		return
	}
	ses.asn.Trace(debug.Id(LoginReqId), "rx", req, "login",
		&ses.Keys.Client.Login, &sig)
	err = os.ErrPermission
	login := &ses.Keys.Client.Login
	ses.user = ses.asn.repos.users.User(login)
	switch {
	case bytes.Equal(ses.Keys.Client.Login.Bytes(),
		ses.cfg.Keys.Admin.Pub.Encr.Bytes()):
		if sig.Verify(ses.cfg.Keys.Admin.Pub.Auth, login[:]) {
			ses.asn.Set("admin")
			err = nil
		}
	case bytes.Equal(ses.Keys.Client.Login.Bytes(),
		ses.cfg.Keys.Server.Pub.Encr.Bytes()):
		if sig.Verify(ses.cfg.Keys.Server.Pub.Auth, login[:]) {
			ses.asn.Set("server")
			err = nil
		}
	default:
		if ses.user != nil &&
			sig.Verify(ses.user.cache.Auth(), login[:]) {
			ses.asn.Set(login.ShortString())
			err = nil
		}
	}
	if err == nil {
		var nonce Nonce
		rand.Reader.Read(nonce[:])
		pub, sec, _ := NewRandomEncrKeys()
		ses.asn.Ack(req, pub.Bytes(), nonce.Bytes())
		ses.Keys.Server.Ephemeral = *pub
		ses.asn.Set(NewBox(2, &nonce, &ses.Keys.Client.Ephemeral,
			&ses.Keys.Server.Ephemeral, sec))
		if ses.user != nil {
			ses.user.logins += 1
			if id := ses.user.cache.ID(); id != "" {
				ses.asn.Set(id)
			}
		}
		ses.asn.Log("login @", time.Now(),
			"\n\tuser: ", &ses.Keys.Client.Login,
			"\n\tclient:", &ses.Keys.Client.Ephemeral,
			"\n\tserver:", &ses.Keys.Server.Ephemeral,
			"\n\tnonce: ", &nonce,
		)
		ses.asn.state = established
	} else {
		ses.asn.Log("failed login:", &ses.Keys.Client.Login, err)
		ses.asn.Ack(req, err)
	}
	return
}

func (ses *Ses) Send(k *PubEncr, f *file.File) {
	f.Seek(0, os.SEEK_SET)
	ses.ForEachLogin(func(x *Ses) {
		if x == ses { // Skip this session
			return
		}
		if bytes.Equal(x.Keys.Client.Login.Bytes(), k.Bytes()) {
			if dup, err := f.Dup(); err != nil {
				ses.asn.Diag(err)
			} else {
				ses.asn.Fixme(f.Name(), "sent to", k)
				x.asn.Tx(NewPDUFile(dup))
			}
		}
	})
}

func (ses *Ses) Set(v interface{}) error {
	switch t := v.(type) {
	case *Config:
		ses.cfg = t
		ses.Mutex.Set(t.Name)
		ses.asn.name.local = t.Name
		ses.asn.Set("unnamed")
	case func(func(*Ses)):
		ses.ForEachLogin = t
	case *Repos:
		ses.asn.repos = t
	default:
		return os.ErrInvalid
	}
	return nil
}
