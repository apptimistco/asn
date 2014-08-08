// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package time

import (
	"fmt"
	"testing"
)

func Test(t *testing.T) {
	x := Now()
	b := x.BigEndianUnix()
	y, _ := BigEndianUnix(b[:])
	if !x.Equal(y) {
		t.Error(x, "!=", y)
	}
	fmt.Println("x:", x)
	fmt.Println("b:", b)
	fmt.Println("y:", y)
}
