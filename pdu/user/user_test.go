// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package user

import (
	"github.com/apptimistco/asn/pdu/reflection"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/encr"
	"testing"
)

func Test(t *testing.T) {
	pubEncr, _, _ := encr.NewRandomKeys()
	pubAuth, secAuth, _ := auth.NewRandomKeys()
	sig := secAuth.Sign(pubEncr[:])
	name := "jane doe"
	fbuid := "jane.doe@facebook.com"
	fbtoken := "123"

	pass := reflection.Check(NewAddReq(Actual, name, fbuid, fbtoken, pubEncr, pubAuth))
	pass = pass && reflection.Check(NewDelReq(pubEncr))
	pass = pass && reflection.Check(NewSearchReq(SearchByName, "j.*doe"))
	pass = pass && reflection.Check(NewVouchReq(pubEncr, sig, false))
	if !pass {
		t.Fail()
	}
}
