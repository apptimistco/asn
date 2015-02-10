// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"io"
	"testing"

	"github.com/apptimistco/asn/debug"
)

func TestFile(t *testing.T) {
	debug.Diag.Redirect("test.log")
	f, err := Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dup, err := f.Dup()
	if err != nil {
		t.Fatal(err)
	}
	defer dup.Close()
	io.WriteString(dup, "this is a test\n")
}
