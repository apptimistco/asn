// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/apptimistco/asn/debug/accumulator"
)

const (
	MarkSz        = 8
	MarkeySz      = 8
	MarkETAMask   = uint8(0x0f)
	MarkPlaceMask = uint8(0xf0)
	MarkPlaceFlag = uint8(0x70)
	MarkPlaceSz   = 7
	MDegree       = 1000000
)

type Mark struct {
	Key Markey
	Loc MarkLoc
}

func (m *Mark) Bytes() []byte { return m.Loc.Bytes() }

func (m *Mark) Has(v interface{}) bool {
	switch t := v.(type) {
	case Markey:
		return m.Key == t
	case MarkLoc:
		return m.Loc == t
	}
	return false
}

func (m *Mark) ReadFrom(r io.Reader) (n int64, err error) {
	var a accumulator.Int64
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
	}()
	a.Accumulate64(m.Key.ReadFrom(r))
	a.Accumulate64(m.Loc.ReadFrom(r))
	return
}

func (m *Mark) Reset() {
	*m = Mark{}
}

func (m *Mark) Set(v interface{}) error {
	switch t := v.(type) {
	case MarkLoc:
		m.Loc = t
	case *MarkLoc:
		m.Loc = *t
	case string:
		if t[0] != '7' {
			b, err := hex.DecodeString(t)
			if err != nil {
				return err
			}
			copy(m.Loc.Bytes(), b[:MarkSz])
		}
	default:
		return os.ErrInvalid
	}
	return nil
}

func (m *Mark) String() string {
	return fmt.Sprint("mark: ", m.Key.String(), " ", m.Loc.String())
}

func (m *Mark) WriteTo(w io.Writer) (n int64, err error) {
	var a accumulator.Int64
	defer func() {
		if r := recover(); r != nil {
			err, _ = r.(error)
		}
		n = int64(a)
	}()
	a.Accumulate64(m.Key.WriteTo(w))
	a.Accumulate64(m.Loc.WriteTo(w))
	return
}

type Markey [MarkeySz]byte

func (key *Markey) Bytes() []byte { return key[:] }

func (key *Markey) Set(v interface{}) (err error) {
	switch t := v.(type) {
	case []byte:
		copy(key.Bytes(), t[:MarkeySz])
	case *Markey:
		copy(key.Bytes(), t.Bytes())
	case *PubEncr:
		copy(key.Bytes(), t[:MarkeySz])
	default:
		err = os.ErrInvalid
	}
	return
}

func (key *Markey) ReadFrom(r io.Reader) (n int64, err error) {
	i, err := r.Read(key[:])
	n = int64(i)
	return
}

func (k Markey) String() string { return hex.EncodeToString(k[:]) }

func (key *Markey) WriteTo(w io.Writer) (n int64, err error) {
	i, err := w.Write(key[:])
	n = int64(i)
	return
}

type MarkLoc [MarkSz]byte

func NewMarkLoc(args ...string) (loc *MarkLoc, err error) {
	if len(args) != 2 {
		err = os.ErrInvalid
		return
	}
	loc = new(MarkLoc)
	for i, arg := range args[:2] {
		var f float64
		if f, err = strconv.ParseFloat(arg, 64); err != nil {
			break
		}
		beg := i * 4
		end := beg + 4
		u := uint32((int32(f * 1000000)))
		binary.BigEndian.PutUint32(loc[beg:end], u)
	}
	return
}

func (loc *MarkLoc) Bytes() []byte { return loc[:] }

// MLL returns the mark's latitude and longitude in degree millionths
func (loc *MarkLoc) MLL() (mlat, mlon int32) {
	mlat = int32(binary.BigEndian.Uint32(loc[:4]))
	mlon = int32(binary.BigEndian.Uint32(loc[4:]))
	return
}

// LL returns the mark's floating point latitude and longitude
func (loc *MarkLoc) LL() (ll MarkLL) {
	mlat, mlon := loc.MLL()
	ll.Lat = float64(mlat) / MDegree
	ll.Lon = float64(mlon) / MDegree
	return
}

func (loc *MarkLoc) IsPlace() bool {
	return (loc[0] & MarkPlaceMask) == MarkPlaceFlag
}

func (loc *MarkLoc) ETA() uint8 { return uint8(loc[0] & MarkETAMask) }

func (loc *MarkLoc) Place() MarkPlace { return loc[1:] }

func (loc *MarkLoc) ReadFrom(r io.Reader) (n int64, err error) {
	i, err := r.Read(loc[:])
	n = int64(i)
	return
}

func (loc *MarkLoc) String() string {
	if loc.IsPlace() {
		return fmt.Sprint(loc.Place(), " ", loc.ETA())
	} else {
		ll := loc.LL()
		return ll.String()
	}
}

func (loc *MarkLoc) WriteTo(w io.Writer) (n int64, err error) {
	i, err := w.Write(loc[:])
	n = int64(i)
	return
}

type MarkPlace []byte

func (p MarkPlace) String() string { return hex.EncodeToString(p) }

type MarkLL struct{ Lat, Lon float64 }

func (ll *MarkLL) String() string {
	return fmt.Sprintf("%0.6f %0.6f", ll.Lat, ll.Lon)
}
