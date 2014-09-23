// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"bytes"
	"github.com/apptimistco/asn"
	"testing"
)

func TestName(t *testing.T) {
	b := &bytes.Buffer{}
	x := "asn/author"
	xname := asn.Name(x)
	xname.WriteTo(b)
	if l, xl := b.Len(), len(x)+1; l != xl {
		t.Error("b.Len():", l, "vs.", xl)
	}
	var name asn.Name
	name.ReadFrom(b)
	if !name.Equal(x) {
		t.Error("name:", name, "vs.", x)
	} else if xname != name {
		t.Error("name:", name, "vs.", xname)
	} else if s := name.Index(); s != "asn" {
		t.Error("index:", s, "vs.", "asn")
	}
}

func TestNameNoIndex(t *testing.T) {
	b := &bytes.Buffer{}
	x := "author"
	xname := asn.Name(x)
	xname.WriteTo(b)
	if l, xl := b.Len(), len(x)+1; l != xl {
		t.Error("b.Len():", l, "vs.", xl)
	}
	var name asn.Name
	name.ReadFrom(b)
	if !name.Equal(x) {
		t.Error("name:", name, "vs.", x)
	} else if xname != name {
		t.Error("name:", name, "vs.", xname)
	} else if s := name.Index(); s != "" {
		t.Error("index:", s, "vs.", "")
	}
}

func TestNameEmpty(t *testing.T) {
	b := &bytes.Buffer{}
	x := ""
	xname := asn.Name(x)
	xname.WriteTo(b)
	if l, xl := b.Len(), len(x)+1; l != xl {
		t.Error("b.Len():", l, "vs.", xl)
	}
	var name asn.Name
	name.ReadFrom(b)
	if !name.Equal(x) {
		t.Error("name:", name, "vs.", x)
	} else if xname != name {
		t.Error("name:", name, "vs.", xname)
	} else if s := name.Index(); s != "" {
		t.Error("index:", s, "vs.", "")
	}
}
