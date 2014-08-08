// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package time wraps the standard library to provide big-endian conversion.
package time

import (
	"encoding/binary"
	"time"
)

type Time time.Time

func Now() Time { return Time(time.Now()) }

// BigEndianUnix returns the Time and length of the big-endian Unix epoch
// retrieved from the given byte slice.
func BigEndianUnix(b []byte) (Time, int) {
	const l = 8
	return Time(time.Unix(int64(binary.BigEndian.Uint64(b[:l])), 0)), l
}

// BigEndianUnix returns a big-endian, Unix epoch byte slice from the subject
// Time.
func (t Time) BigEndianUnix() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.Unix()))
	return b
}

// Equal compares the subject and given Time values after masking their
// nanosecond remainders.
func (x Time) Equal(y Time) bool { return x.Unix() == y.Unix() }

// String returns the RFC822 format of the subject Time
func (t Time) String() string {
	return time.Time(t).Format(time.RFC822Z)
}

// Unix returns the Unix epoch seconds of the subject Time.
func (t Time) Unix() int64 { return time.Time(t).Unix() }
