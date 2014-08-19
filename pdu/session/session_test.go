// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"github.com/apptimistco/asn/pdu/reflection"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/encr"
	"testing"
)

func Test(t *testing.T) {
	pubEncr, _, _ := encr.NewRandomKeys()
	_, secAuth, _ := auth.NewRandomKeys()
	sig := secAuth.Sign(pubEncr[:])
	url := "ws://siren.apptimist.co/ws/asn/loc?key=" + pubEncr.String()

	pass := reflection.Check(NewLoginReq(pubEncr, sig))
	pass = pass && reflection.Check(NewRedirectReq(url))
	pass = pass && reflection.Check(NewResumeReq())
	pass = pass && reflection.Check(NewQuitReq())
	if !pass {
		t.Fail()
	}
}
