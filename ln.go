// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"path/filepath"

	"github.com/apptimistco/asn/debug"

	"os"
	"syscall"
)

// LN creates directories if required; unlinks dst if it exists; then hard
// links dst with src.  LN panic's on error so the calling function must
// recover.
func LN(src, dst string) {
	dn := filepath.Dir(dst)
	if _, err := os.Stat(dn); err != nil {
		if !os.IsNotExist(err) {
			panic(err)
		}
		if err := MkdirAll(dn); err != nil {
			panic(err)
		}
	}
	if _, err := os.Stat(dst); err == nil {
		if err = syscall.Unlink(dst); err != nil {
			panic(err)
		}
	}
	if err := syscall.Link(src, dst); err != nil {
		panic(err)
	}
	Debug.Fixme(debug.Depth(2), "ln", src, dst)
}
