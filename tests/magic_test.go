// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"bytes"
	"github.com/apptimistco/asn"
	"testing"
)

func TestMagic(t *testing.T) {
	b := &bytes.Buffer{}
	asn.WriteMagicTo(b)
	if _, err := asn.ReadMagicFrom(b); err != nil {
		t.Error(err)
	}
}

func TestNotMagic(t *testing.T) {
	var nm [asn.MagicSz]byte
	copy(nm[:], []byte("notmagic"))
	b := &bytes.Buffer{}
	b.Write(nm[:])
	if _, err := asn.ReadMagicFrom(b); err != asn.ErrNotMagic {
		t.Error(err)
	}
}
