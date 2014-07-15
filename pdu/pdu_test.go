// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdu

import (
	"fmt"
	"os"
)

var out = os.Stdout // use this writer for Examples with unspecified Output

// Show PDU Ids per version.
func ExampleIds() {
	fmt.Fprintf(out, "%30s%s\n", "", "Version")
	fmt.Fprintf(out, "%30s", "")
	for v := uint8(0); v <= Version; v++ {
		fmt.Fprintf(out, "%4d", v)
	}
	fmt.Fprintln(out)
	for id := Id(0); id < NpduIds; id++ {
		fmt.Fprintf(out, "%8d.", id)
		if s := id.String(); len(s) > 0 {
			fmt.Fprintf(out, "%21s", s+"Id")
			for v := uint8(0); v <= Version; v++ {
				fmt.Fprintf(out, "%4d", id.Version(v))
			}
		}
		fmt.Fprintln(out)
	}
	// Output:
}

// Show Error codes per version.
func ExampleErrs() {
	fmt.Fprintf(out, "%30s%s\n", "", "Version")
	fmt.Fprintf(out, "%30s", "")
	for v := uint8(0); v <= Version; v++ {
		fmt.Fprintf(out, "%4d", v)
	}
	fmt.Fprintln(out)
	for id := NpduIds; id < Ncounters; id++ {
		fmt.Fprintf(out, "%8d.", id-SuccessId)
		if s := id.String(); len(s) > 0 {
			if id == SuccessId {
				fmt.Fprintf(out, "%21s", s)
			} else {
				fmt.Fprintf(out, "%21s", s+"Err")
			}
			for v := uint8(0); v <= Version; v++ {
				fmt.Fprintf(out, "%4d", id.Err().Version(v))
			}
		}
		fmt.Fprintln(out)
	}
	// Output:
}
