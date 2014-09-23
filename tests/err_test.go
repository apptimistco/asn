// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"fmt"
	"github.com/apptimistco/asn"
	"testing"
)

// Show Error codes per version.
func TestErrs(t *testing.T) {
	if !testing.Verbose() {
		t.SkipNow()
	}
	fmt.Printf("%25s%s\n", "", "Version")
	fmt.Printf("%25s", "")
	for v := asn.Version(0); v <= asn.Latest; v++ {
		fmt.Printf("%4d", v)
	}
	fmt.Println()
	for ecode, s := range asn.ErrStrings {
		fmt.Printf("%8d.", ecode)
		fmt.Printf("%16s", s)
		for v := asn.Version(0); v <= asn.Latest; v++ {
			fmt.Printf("%4d", asn.Err(ecode).Version(v))
		}
		fmt.Println()
	}
}
