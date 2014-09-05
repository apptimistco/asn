// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package object_test

import (
	"bytes"
	"fmt"
	"github.com/apptimistco/asn/object"
	"github.com/apptimistco/datum"
	"github.com/apptimistco/encr"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	buf    = &bytes.Buffer{}
	objdir []os.FileInfo
)

func init() {
	dot, err := os.Open(".")
	if err == nil {
		defer dot.Close()
		objdir, _ = dot.Readdir(0)
	}
}

func TestMagic(t *testing.T) {
	var m object.Magic
	buf.Reset()
	object.MagicString.WriteTo(buf)
	m.ReadFrom(buf)
	if !m.IsMagic() {
		t.Error("not magic")
	}
}

func TestCodes(t *testing.T) {
	var c object.Code
	buf.Reset()
	object.BlobCode.WriteTo(buf)
	object.ASNCode.WriteTo(buf)
	object.UserCode.WriteTo(buf)
	object.PackCode.WriteTo(buf)
	c.ReadFrom(buf)
	if !c.IsBlob() {
		t.Error("not Blob")
	}
	c.ReadFrom(buf)
	if !c.IsASN() {
		t.Error("not ASN tree")
	}
	c.ReadFrom(buf)
	if !c.IsUser() {
		t.Error("not User tree")
	}
	c.ReadFrom(buf)
	if !c.IsPack() {
		t.Error("not Pack")
	}
}

func TestHeader(t *testing.T) {
	var h object.Header
	buf.Reset()
	pub, _, _ := encr.NewRandomKeys()
	(&object.Header{Owner: *pub, Author: *pub}).WriteTo(buf)
	h.ReadFrom(buf)
	if h.Owner != *pub {
		t.Errorf("Owner mismatch %x vs. %x\n", h.Owner, *pub)
	}
	if h.Author != *pub {
		t.Errorf("Author mismatch %x vs. %x\n", h.Author, *pub)
	}
	println(h.Time.Format(time.RFC822Z))
}

func TestTree(t *testing.T) {
	var in, out object.Tree
	buf.Reset()
	for _, fi := range objdir {
		if strings.HasSuffix(fi.Name(), ".go") {
			d, err := datum.Open(fi.Name())
			if err != nil {
				t.Error(err)
			} else {
				out.Append(d.SHA(), fi.Name())
				datum.Push(&d)
			}
		}
	}
	out.WriteTo(buf)
	in.ReadFrom(buf)
	if len(out) != len(in) {
		t.Fatal("Tree len mismatch", len(in), "vs.", len(out))
	}
	for i, e := range in {
		if e.Sum != out[i].Sum {
			t.Error(i, "Sum mismatch", e.Sum.String()[:8],
				"vs.", out[i].Sum.String()[:8])
		} else if e.Name != out[i].Name {
			t.Error(i, "Name mismatch", e.Name, out[i].Name)
		} else {
			fmt.Println(e.Sum.String()[:8], e.Name)
		}
	}
	datum.Flush()
}

func TestPack(t *testing.T) {
	var in, out object.Pack
	pack := datum.Pull()
	defer func() {
		for _, d := range in {
			datum.Push(&d)
		}
		for _, d := range out {
			datum.Push(&d)
		}
		datum.Push(&pack)
		datum.Flush()
	}()
	for _, fi := range objdir {
		if strings.HasSuffix(fi.Name(), ".go") {
			d, err := datum.Open(fi.Name())
			if err != nil {
				t.Error(err)
			} else {
				out.Append(d)
			}
		}
	}
	out.WriteTo(pack)
	in.ReadFrom(pack)
	if len(in) != len(out) {
		t.Fatal("Pack len mismatch", len(in), "vs.", len(out))
	}
	for i, e := range in {
		if inlen, outlen := e.Len(), out[i].Len(); inlen != outlen {
			t.Error(i, "len mismatch", inlen, "vs.", outlen)
		} else if isum, osum := e.SHA(), out[i].SHA(); isum != osum {
			t.Error(i, "SHA mismatch", isum.String()[:8],
				"vs.", osum.String()[:8])
		} else {
			fmt.Println(isum.String()[:8])
		}
	}
}
