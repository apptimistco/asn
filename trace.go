// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"sync"
)

const DefaultRingSize = 32

var (
	ringMutex *sync.Mutex
	ring      []string
	unfilter  [Nids]bool

	ringIndex, ringSize int
)

func init() {
	ringIndex, ringSize = 0, DefaultRingSize
	ring = make([]string, ringSize)
	ringMutex = new(sync.Mutex)
	TraceUnfilter(Nids)
	TraceFilter(RawId)
}

// Println formats the given operands with space separation to the log ring
// prefixed by the ASN session Name.
func (asn *ASN) Println(a ...interface{}) (n int, err error) {
	ringMutex.Lock()
	defer ringMutex.Unlock()
	ring[ringIndex] = asn.Name.Session + " " + fmt.Sprintln(a...)
	n = len(ring[ringIndex])
	ringIndex += 1
	if ringIndex == ringSize {
		ringIndex = 0
	}
	return
}

// Trace provides filtered println to log ring.
func (asn *ASN) Trace(v ...interface{}) (n int, err error) {
	var id Id
	var ok bool
	for _, t := range v {
		if id, ok = t.(Id); ok {
			break
		}
	}
	if ok && id < Nids && unfilter[id] {
		n, err = asn.Println(v...)
	}
	return
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

// TraceFlush writes; then empties the trace ring buffer.
func TraceFlush(out io.Writer) {
	ringMutex.Lock()
	defer func() {
		ringIndex = 0
		ringMutex.Unlock()
	}()
	for i, s := range ring[ringIndex+1:] {
		if s != "" {
			io.WriteString(out, s)
			ring[i] = ""
		}
	}
	for i, s := range ring[:ringIndex] {
		if s != "" {
			io.WriteString(out, s)
			ring[i] = ""
		}
	}
}

// TraceFilter PDUs of the given Id; an Id of Nids filters all.
// By default, all PDU types are filtered.
func TraceFilter(id Id) {
	if id < Nids {
		unfilter[id] = false
	} else {
		for i, _ := range unfilter {
			unfilter[i] = false
		}
	}
}

// TraceUnfilter PDUs of the given Id; an Id of Nids unfilters all.
func TraceUnfilter(id Id) {
	if id < Nids {
		unfilter[id] = true
	} else {
		for i, _ := range unfilter {
			unfilter[i] = true
		}
	}
}
