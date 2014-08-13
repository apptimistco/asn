// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"github.com/apptimistco/asn/pdu/reflection"
	"testing"
)

func Test(t *testing.T) {
	fname := "foo/bar"
	pass := reflection.Check(NewLockReq(fname))
	pass = pass && reflection.Check(NewReadReq(fname))
	pass = pass && reflection.Check(NewRemoveReq(fname))
	pass = pass && reflection.Check(NewWriteReq(fname))
	if !pass {
		t.Fail()
	}
}
