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

// Println formats the given operands with space separation to the log ring.
func Println(a ...interface{}) (n int, err error) {
	ringMutex.Lock()
	defer ringMutex.Unlock()
	ring[ringIndex] = fmt.Sprintln(a...)
	n = len(ring[ringIndex])
	ringIndex += 1
	if ringIndex == ringSize {
		ringIndex = 0
	}
	return
}

// Trace provides filtered println to log ring.
func Trace(id Id, v ...interface{}) {
	if id < NpduIds && unfilter[id] {
		Println(v...)
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
	defer func() {
		ringIndex = 0
		ringMutex.Unlock()
	}()
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

func (req *TraceReq) Format(version uint8, h Header) {
	var arg uint8
	switch req.Cmd {
	case TraceReqFilter, TraceReqUnfilter:
		arg = Id(req.Arg).Version(version)
	case TraceReqFlush:
	case TraceReqResize:
		arg = req.Arg
	}
	h.Write([]byte{version,
		TraceReqId.Version(version),
		req.Cmd,
		arg})
}

func (req *TraceReq) Id() Id { return TraceReqId }

func (req *TraceReq) Parse(h Header) Err {
	buf := []byte{0, 0, 0, 0}
	if n, err := h.Read(buf); err != nil || n != len(buf) {
		return IlFormatErr
	}
	req.Cmd = buf[2]
	req.Arg = buf[3]
	return Success
}

func (req *TraceReq) String() string {
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
