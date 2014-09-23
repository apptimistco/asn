// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"bytes"
	"github.com/apptimistco/asn"
	"github.com/apptimistco/encr"
	"testing"
	"time"
)

func TestObj(t *testing.T) {
	var o asn.Obj
	b := &bytes.Buffer{}
	pub, _, _ := encr.NewRandomKeys()
	(&asn.Obj{Owner: *pub, Author: *pub}).WriteTo(b)
	o.ReadFrom(b)
	if o.Owner != *pub {
		t.Errorf("Owner mismatch %x vs. %x\n", o.Owner, *pub)
	}
	if o.Author != *pub {
		t.Errorf("Author mismatch %x vs. %x\n", o.Author, *pub)
	}
	if testing.Verbose() {
		println("obj.Time:", o.Time.Format(time.RFC822Z))
	}
}
