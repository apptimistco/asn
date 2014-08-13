// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package time wraps the standard library to truncate nsec and provide
// RFC822 String() format.
package time

import (
	"time"
)

type Time struct{ time.Time }

func Now() Time {
	return Time{time.Unix(time.Now().Unix(), 0)}
}

func Unix(sec, nsec int64) Time {
	return Time{time.Unix(sec, nsec)}
}

// Equal compares the subject and given Time values after masking their
// nanosecond remainders.
func (x Time) Equal(y Time) bool { return x.Unix() == y.Unix() }

// String returns the RFC822 format of the subject Time
func (t Time) String() string {
	return t.Format(time.RFC822Z)
}
