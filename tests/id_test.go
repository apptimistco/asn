// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tests

import (
	"fmt"
	"github.com/apptimistco/asn"
	"testing"
)

// Show PDU Ids per version.
func TestIds(t *testing.T) {
	if !testing.Verbose() {
		t.Skip()
	}
	fmt.Printf("%25s%s\n", "", "Version")
	fmt.Printf("%25s", "")
	for v := asn.Version(0); v <= asn.Latest; v++ {
		fmt.Printf("%4d", v)
	}
	fmt.Println()
	for id := asn.RawId + 1; id < asn.Nids; id++ {
		fmt.Printf("%8d.", id)
		if s := id.String(); len(s) > 0 {
			fmt.Printf("%16s", s+"Id")
			for v := asn.Version(0); v <= asn.Latest; v++ {
				fmt.Printf("%4d", id.Version(v))
			}
		}
		fmt.Println()
	}
}
