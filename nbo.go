// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"io"
	"math"
	"time"
)

type AnonymousNBOReader io.Reader
type AnonymousNBOWriter io.Writer
type NBOReader struct{ AnonymousNBOReader }
type NBOWriter struct{ AnonymousNBOWriter }

// ReadNBO is an io.Reader wrapper that reads; then converts the Network Byte
// Order number before storing at the given pointer. This returns the number of
// bytes read along with any errors.
//
// Usage:
//	var u unit64
//	var f float64
//	(NBOReader{r}).ReadNBO(&u)
//	(NBOReader{r}).ReadNBO(&f)
func (r NBOReader) ReadNBO(v interface{}) (n int, err error) {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	switch t := v.(type) {
	case *uint8:
		if n, err = r.Read(b[:1]); err == nil {
			*t = b[0]
		}
	case *int8:
		if n, err = r.Read(b[:1]); err == nil {
			*t = int8(b[0])
		}
	case *uint16:
		if n, err = r.Read(b[:2]); err == nil {
			*t = binary.BigEndian.Uint16(b[:2])
		}
	case *int16:
		if n, err = r.Read(b[:1]); err == nil {
			*t = int16(binary.BigEndian.Uint16(b[:2]))
		}
	case *uint32:
		if n, err = r.Read(b[:4]); err == nil {
			*t = binary.BigEndian.Uint32(b[:4])
		}
	case *int32:
		if n, err = r.Read(b[:4]); err == nil {
			*t = int32(binary.BigEndian.Uint32(b[:4]))
		}
	case *uint64:
		if n, err = r.Read(b[:8]); err == nil {
			*t = binary.BigEndian.Uint64(b[:8])
		}
	case *int64:
		if n, err = r.Read(b[:1]); err == nil {
			*t = int64(binary.BigEndian.Uint64(b[:8]))
		}
	case *float64:
		if n, err = r.Read(b[:8]); err == nil {
			bits := binary.BigEndian.Uint64(b[:8])
			*t = math.Float64frombits(bits)
		}
	case *time.Time:
		if n, err = r.Read(b[:8]); err == nil {
			nanoepoch := int64(binary.BigEndian.Uint64(b[:8]))
			isec := int64(time.Second)
			*t = time.Unix(nanoepoch/isec, nanoepoch%isec)
		}
	}
	return
}

// WriteNBO is an io.Writer wrapper that converts the given number to Network
// Byte Order before writing to the associated writer.  This returns the number
// of bytes writen along with any errors.
//
// Usage:
//	(NBOWriter{w}).WriteNBO(uint64(0x1234))
//	(NBOWriter{w}).WriteNBO(98.6)
//	...
func (w NBOWriter) WriteNBO(v interface{}) (n int, err error) {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	switch t := v.(type) {
	case uint8:
		b[0] = t
		n, err = w.Write(b[:1])
	case int8:
		b[0] = uint8(t)
		n, err = w.Write(b[:1])
	case uint16:
		binary.BigEndian.PutUint16(b[:2], t)
		n, err = w.Write(b[:2])
	case int16:
		u := uint16(t)
		binary.BigEndian.PutUint16(b[:2], u)
		n, err = w.Write(b[:2])
	case uint32:
		binary.BigEndian.PutUint32(b[:4], t)
		n, err = w.Write(b[:4])
	case int32:
		u := uint32(t)
		binary.BigEndian.PutUint32(b[:4], u)
		n, err = w.Write(b[:4])
	case uint64:
		binary.BigEndian.PutUint64(b[:8], t)
		n, err = w.Write(b[:8])
	case int64:
		u := uint64(t)
		binary.BigEndian.PutUint64(b[:8], u)
		n, err = w.Write(b[:8])
	case float64:
		binary.BigEndian.PutUint64(b[:8], math.Float64bits(t))
		n, err = w.Write(b[:8])
	case time.Time:
		binary.BigEndian.PutUint64(b[:8], uint64(t.UnixNano()))
		n, err = w.Write(b[:8])
	}
	return
}
