// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !diag

package asn

import (
	"io/ioutil"
	"log"
)

var Diag *log.Logger

func init() { Diag = log.New(ioutil.Discard, "", 0) }
