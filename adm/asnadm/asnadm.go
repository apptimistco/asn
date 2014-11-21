// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asnadm provides a main wrapper to github.com/apptimistco/asn/adm
package main

import (
	"github.com/apptimistco/asn/adm"
	"os"
)

var Exit = os.Exit

func main() {
	if err := adm.Main(os.Args...); err != nil {
		nl := []byte{'\n'}
		s := err.Error()
		os.Stderr.WriteString(s)
		if s[len(s)-1] != nl[0] {
			os.Stderr.Write(nl)
		}
		Exit(1)
	}
}
