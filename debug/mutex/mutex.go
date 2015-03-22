// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package mutex provides a wrapper interface to sync.Mutex that, when built with
both "diag" and "mutex" tags (e.g. go build -tags "diag mutex"), will log each
Lock() and Unlock() to the diagnostic file or syslog.

Usage ("./foo.go"):

	package main

	import (
		"github.com/apptimistco/asn/debug"
		"github.com/apptimistco/asn/debug/mutex"
	)

	var foo struct {
		mutex.Mutex
		...
	}

	func main() {
		foo.Mutex.Set("foo")
		if false {
			debug.Diag.Redirect("foo.diag")
		}
		foo.Lock()		// line: X
		defer foo.Unlock()
		...
		return			// line: Y
	}

build and run,

	$ go build -tags "diag mutex" .
	$ ./foo

would syslog this at level DEBUG,

	foo.go:X: foo lock
	foo.go:Y: foo unlock

with the Redirect(), this is printed to the named file instead of syslog.
*/
package mutex

import (
	"sync"

	"github.com/apptimistco/asn/debug"
)

type Mutex struct {
	sync.Mutex
	debug.Debug
}
