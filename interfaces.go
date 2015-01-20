// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"net"
	"time"
)

// LenReader is a wrapper of something providing io.Reader and Len()
type LenReader interface {
	Len() int
	io.Reader
}

// LenReadRewinderer is a wrapper of something providing LenReader and Rewind()
type LenReadRewinder interface {
	LenReader
	Rewind() error
}

// Listener extends the net.Listener interface with SetDeadline
type Listener interface {
	// Accept waits for and returns the next connection to the listener.
	Accept() (net.Conn, error)

	// Close closes the listener.
	// Any blocked Accept operations will be unblocked and return errors.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr

	// SetDeadline sets the deadline associated with the listener. A zero
	// time value disables the deadline.
	SetDeadline(time.Time) error
}

// WriterStringer is a wrapper of anything providing the WriteString method.
type WriteStringer interface {
	WriteString(string) (int, error)
}

// Reposer is a wrapper of methods common to both adm and srv used in
// maintaining an ASN repository.
type Reposer interface {
	// Returns the repos directory name.
	DN() string
	IsAdmin(*EncrPub) bool
	IsService(*EncrPub) bool
}
