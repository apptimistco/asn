// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asnkeys provides a main wrapper to github.com/apptimistco/asn/internal/keys
package main

import (
	"github.com/apptimistco/asn/internal/keys"
	"os"
)

var Exit = os.Exit

func main() {
	if err := keys.Main(os.Args...); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Stderr.WriteString("\n")
		Exit(1)
	}
}
