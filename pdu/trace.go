// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdu

import (
	"fmt"
	"sync"
)

const DefaultRingSize = 32

var (
	ringMutex *sync.Mutex
	ring      []string
	unfilter  [NpduIds]bool

	ringIndex, ringSize int
)

const (
	TraceReqFilter uint8 = iota
	TraceReqUnfilter
	TraceReqFlush
	TraceReqResize
)

type TraceReq struct{ Cmd, Arg uint8 }

func init() {
	ringIndex, ringSize = 0, DefaultRingSize
	ring = make([]string, ringSize)
	ringMutex = new(sync.Mutex)
	Register(TraceReqId, func() PDUer { return &TraceReq{} })
}

// Trace provides a filtered and formatted PDU log ring.
// Name is usally the session user name.
// Rxtx shoul be either "Rx" or "Tx".
func Trace(name, rxtx string, id Id, v PDUer, data []byte) {
	if id < NpduIds && unfilter[id] {
		ringMutex.Lock()
		defer ringMutex.Unlock()
		ring[ringIndex] = fmt.Sprintln(name, rxtx, id.String(),
			v.String(data))
		ringIndex += 1
		if ringIndex == ringSize {
			ringIndex = 0
		}
	}
}

// TraceResize empties; then resizes the trace ring.
func TraceResize(n int) {
	ringMutex.Lock()
	defer ringMutex.Unlock()
	for i := range ring {
		ring[i] = ""
	}
	if n > ringSize {
		if n < cap(ring) {
			ring = ring[:n]
		} else {
			ring = ring[:cap(ring)]
			for i := cap(ring); i < n; i++ {
				ring = append(ring, "")
			}
		}
	}
	ringSize = n
}

// WriterStringer is a wrapper of anything providing the WriteString method.
type WriteStringer interface {
	WriteString(string) (int, error)
}

// TraceFlush writes; then empties the trace ring buffer.
func TraceFlush(out WriteStringer) {
	ringMutex.Lock()
	defer ringMutex.Unlock()
	for i, s := range append(ring[ringIndex+1:], ring[:ringIndex]...) {
		if len(s) != 0 {
			out.WriteString(s)
			ring[i] = ""
		}
	}
}

// TraceFilter PDUs of the given Id; an Id of NpduIds filters all.
// By default, all PDU types are filtered.
func TraceFilter(id Id) {
	if id < NpduIds {
		unfilter[id] = false
	} else {
		for i, _ := range unfilter {
			unfilter[i] = false
		}
	}
}

// TraceUnfilter PDUs of the given Id; an Id of NpduIds unfilters all.
func TraceUnfilter(id Id) {
	if id < NpduIds {
		unfilter[id] = true
	} else {
		for i, _ := range unfilter {
			unfilter[i] = true
		}
	}
}

func NewTraceReq(cmd, arg uint8) *TraceReq {
	return &TraceReq{Cmd: cmd, Arg: arg}
}

func (req *TraceReq) Format(version uint8) []byte {
	var arg uint8
	switch req.Cmd {
	case TraceReqFilter, TraceReqUnfilter:
		arg = Id(req.Arg).Version(version)
	case TraceReqFlush:
	case TraceReqResize:
		arg = req.Arg
	}
	return []byte{version, TraceReqId.Version(version), req.Cmd, arg}
}

func (req *TraceReq) Parse(header []byte) Err {
	if len(header) < 1+1+1+1 {
		return IlFormatErr
	}
	req.Cmd = header[2]
	req.Arg = header[3]
	return Success
}

func (req *TraceReq) String(data []byte) string {
	switch req.Cmd {
	case TraceReqFilter:
		return "Filter " + Id(req.Arg).String()
	case TraceReqUnfilter:
		return "Unfilter " + Id(req.Arg).String()
	case TraceReqFlush:
		return "Flush"
	case TraceReqResize:
		return fmt.Sprintf("Resize %d", req.Arg)
	}
	return "unknown"
}
