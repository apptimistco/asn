// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"os"
)

type Buffer struct{ bytes.Buffer }

func (b *Buffer) Close() error { return nil }

func (b *Buffer) Has(v interface{}) bool {
	switch t := v.(type) {
	case string:
		return b.String() == t
	case []byte:
		return bytes.Equal(b.Bytes(), t)
	}
	return false
}

func (b *Buffer) Set(v interface{}) (err error) {
	switch t := v.(type) {
	case string:
		b.Reset()
		_, err = b.WriteString(t)
	case []byte:
		b.Reset()
		_, err = b.Write(t)
	default:
		err = os.ErrInvalid
	}
	return
}
