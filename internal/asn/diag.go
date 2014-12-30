// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build diag

package asn

import (
	"fmt"
	"log"
	"os"
)

var Diag *log.Logger

func init() {
	name := fmt.Sprint("asn_", os.Getpid(), ".diag")
	f, err := os.Create(name)
	if err != nil {
		panic("can't create diag log file: " + err.Error())
	}
	Diag = log.New(f, "", log.Lshortfile)
}

func (asn *ASN) Diag(v ...interface{}) {
	Diag.Output(2, asn.Name.Session+" "+fmt.Sprintln(v...))
}

func (asn *ASN) Diagf(format string, v ...interface{}) {
	Diag.Output(2, asn.Name.Session+" "+fmt.Sprintf(format, v...))
}
