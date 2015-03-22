// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"net"
	"time"

	"github.com/apptimistco/asn/debug/file"
)

type Blobber interface {
	Blobber(func(string) error, io.Reader, ...string) error
}
type Byter interface {
	Bytes() []byte
}
type EncodeToStringer interface {
	EncodeToString() string
}
type Haser interface {
	Has(interface{}) bool
}
type Lener interface {
	Len() int
}
type ReadFromer interface {
	ReadFrom(io.Reader) (int64, error)
}
type Resetter interface {
	Reset()
}
type Rewinder interface {
	Rewind() error
}
type Sender interface {
	Send(*PubEncr, *file.File)
}
type SetDeadliner interface {
	SetDeadline(time.Time) error
}
type Setter interface {
	Set(interface{}) error
}
type Sizer interface {
	Size() int
}
type Stringer interface {
	String() string
}
type WriteStringer interface {
	WriteString(string) (int, error)
}
type WriteToer interface {
	WriteTo(io.Writer) (int64, error)
}

type ByteSizer interface {
	Byter
	Sizer
}

type Cacher interface {
	Byter
	Haser
	ReadFromer
	Resetter
	Setter
	Stringer
	WriteToer
}

type LenReader interface {
	Lener
	io.Reader
}

type LenReadRewinder interface {
	LenReader
	Rewinder
}

// Listener extends the net.Listener interface with SetDeadline
type Listener interface {
	net.Listener
	SetDeadliner
}

type ReadWriteToer interface {
	io.Reader
	WriteToer
}

type ReadCloseWriteToer interface {
	io.Reader
	Close() error
	WriteToer
}
