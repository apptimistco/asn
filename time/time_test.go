// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package time

import (
	"github.com/apptimistco/nbo"
	"github.com/apptimistco/yab"
	"testing"
)

func Test(t *testing.T) {
	buf := yab.New()
	defer buf.Close()
	x := Now()
	(nbo.Writer{buf}).WriteNBO(uint64(x.Unix()))
	var u64 uint64
	(nbo.Reader{buf}).ReadNBO(&u64)
	y := Unix(int64(u64), 0)
	if x != y {
		t.Error("mismatch:", x.String(), "!=", y.String())
	} else {
		println(y.String())
	}
}
