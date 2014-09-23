// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"bytes"
	"github.com/apptimistco/asn"
	"os"
	"strings"
	"testing"
)

func TestSums(t *testing.T) {
	b := &bytes.Buffer{}
	dot, err := os.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := dot.Readdir(0)
	dot.Close()
	var in, out asn.Sums
	for _, fi := range dir {
		if strings.HasSuffix(fi.Name(), ".go") {
			if f, err := os.Open(fi.Name()); err != nil {
				t.Error(err)
			} else {
				sum := asn.NewSumReader(f)
				out = append(out, sum)
				if testing.Verbose() {
					println(fi.Name(), "\t", sum.String())
				}
			}
		}
	}
	out.WriteTo(b)
	in.ReadFrom(b)
	if len(out) != len(in) {
		t.Fatal("Mismatched lengths", len(in), "vs.", len(out))
	}
	for i := range in {
		if in[i] != out[i] {
			t.Error("mismatch @", i, ":", in[i].String()[:8],
				"vs.", out[i].String()[:8])
		}
	}
}
