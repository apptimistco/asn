// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package message

import (
	"github.com/apptimistco/asn/pdu/reflection"
	"github.com/apptimistco/encr"
	"testing"
)

func Test(t *testing.T) {
	to, _, _ := encr.NewRandomKeys()
	from, _, _ := encr.NewRandomKeys()
	var head Id

	pass := reflection.Check(NewHeadRpt(to, &head))
	pass = pass && reflection.Check(NewMessageReq(to, from))
	if !pass {
		t.Fail()
	}
}
