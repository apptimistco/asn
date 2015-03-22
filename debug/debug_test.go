// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"bytes"
	"os"
	"testing"
)

func TestDebug(t *testing.T) {
	var test = struct {
		Debug
		out struct {
			diag, log bytes.Buffer
		}
	}{
		Debug: Debug("test"),
	}
	test.FIXME("hello world")
	test.Diag("hello world")
	test.Log("hello world")
	if testing.Verbose() {
		FIXME.Redirect(os.Stdout)
		Diag.Redirect(os.Stdout)
		Log.Redirect(os.Stdout)
		test.FIXME("hello world")
		test.Diag("hello world")
		test.Log("hello world")
		test.Trace("hello world")
		Trace.WriteTo(os.Stdout)
		n := 4
		Trace.Resize(n)
		for i := 0; i <= 2*n+1; i++ {
			test.Trace(i)
		}
		Trace.WriteTo(os.Stdout)
		Trace.Filter(Id(2))
		for i := 0; i <= n; i++ {
			test.Trace(Id(i), i)
		}
		Trace.WriteTo(os.Stdout)
		Trace.Unfilter(Id(2))
		for i := 0; i <= n; i++ {
			test.Trace(Id(i), i)
		}
		Trace.WriteTo(os.Stdout)
	}
}
