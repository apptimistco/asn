// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"strconv"
)

const (
	MarkFN        = "asn/mark"
	MarkSz        = 8
	MarkeySz      = 8
	MarkETAMask   = uint8(0x0f)
	MarkPlaceMask = uint8(0x70)
	MarkPlaceFlag = uint8(0x70)
	MarkPlaceSz   = 7
	MDegree       = 1000000
)

type Mark struct {
	Key Markey
	Loc MarkLoc
}
type MarkLoc [MarkSz]byte
type MarkPlace []byte
type MarkLL struct{ Lat, Lon float64 }
type Markey [MarkeySz]byte

// MLL returns the mark's latitude and longitude in degree millionths
func (m *Mark) MLL() (mlat, mlon int32) {
	mlat = int32(binary.BigEndian.Uint32(m.Loc[:4]))
	mlon = int32(binary.BigEndian.Uint32(m.Loc[4:]))
	return
}

// LL returns the mark's floating point latitude and longitude
func (m *Mark) LL() (ll MarkLL) {
	mlat, mlon := m.MLL()
	ll.Lat = float64(mlat) / MDegree
	ll.Lon = float64(mlon) / MDegree
	return
}

func (m *Mark) IsPlace() bool {
	return (m.Loc[0] & MarkPlaceMask) == MarkPlaceFlag
}

func (m *Mark) ETA() uint8 {
	return uint8(m.Loc[0] & MarkETAMask)
}

func (m *Mark) Place() MarkPlace {
	return m.Loc[1:]
}

func (m *Mark) ReadFrom(r io.Reader) (n int64, err error) {
	var x N
	defer func() {
		n = int64(x)
	}()
	if err = x.Plus(r.Read(m.Key[:])); err != nil {
		return
	}
	err = x.Plus(r.Read(m.Loc[:]))
	return
}

// SETPlace USER, PLACE, "7?"
func (m *Mark) SetPlace(user, place *EncrPub, flageta string) (err error) {
	copy(m.Key[:], user[:MarkeySz])
	b, err := hex.DecodeString(flageta)
	if err != nil {
		return
	}
	m.Loc[0] = b[0]
	copy(m.Loc[1:], place[:MarkPlaceSz])
	return
}

// SetLL USER, LAT, LON
func (m *Mark) SetLL(user *EncrPub, args ...string) (err error) {
	if len(args) != 2 {
		err = os.ErrInvalid
		return
	}
	copy(m.Key[:], user[:MarkeySz])
	for i, arg := range args[:2] {
		var f float64
		if f, err = strconv.ParseFloat(arg, 64); err != nil {
			break
		}
		beg := i * 4
		end := beg + 4
		u := uint32((int32(f * 1000000)))
		binary.BigEndian.PutUint32(m.Loc[beg:end], u)
	}
	return
}

func (p MarkPlace) String() string {
	return hex.EncodeToString(p)
}

func (k Markey) String() string {
	return hex.EncodeToString(k[:])
}

func (m *Mark) WriteTo(w io.Writer) (n int64, err error) {
	var x N
	defer func() {
		n = int64(x)
	}()
	if err = x.Plus(w.Write(m.Key[:])); err != nil {
		return
	}
	err = x.Plus(w.Write(m.Loc[:]))
	return
}
