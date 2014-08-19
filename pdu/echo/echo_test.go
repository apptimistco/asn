// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package echo

import (
	"github.com/apptimistco/asn/pdu/reflection"
	"testing"
)

func Test(t *testing.T) {
	if !reflection.Check(NewEcho(Request)) {
		t.Fail()
	}
}
