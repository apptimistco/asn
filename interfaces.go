// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

type Byter interface {
	Bytes() []byte
}

func Bytes(x Byter) (b []byte) {
	if x != nil {
		b = x.Bytes()
	}
	return
}

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
	IsAdmin(*PubEncr) bool
	IsService(*PubEncr) bool
}

type Sizer interface {
	Size() int
}

func Size(x Sizer) (l int) {
	if x != nil {
		l = x.Size()
	}
	return
}

type Stringer interface {
	String() string
}

func String(x Stringer) (s string) {
	if x != nil {
		return x.String()
	}
	return
}

type ByteSizer interface {
	Byter
	Sizer
}

func DecodeFromString(x ByteSizer, s string) error {
	if x == nil {
		return errors.New("destination is nil")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != x.Size() {
		return os.ErrInvalid
	}
	copy(x.Bytes()[:], b[:])
	return nil
}

func EncodeToString(x Byter) string {
	return hex.EncodeToString(x.Bytes())
}

func GetYAML(x Stringer) (string, interface{}) {
	return "", x.String()
}

func SetYAML(x ByteSizer, t string, v interface{}) bool {
	if s, ok := v.(string); ok && len(s) > 0 {
		if err := DecodeFromString(x, s); err != nil {
			return true
		}
	}
	return false
}
