// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !notrace

package debug

import "bytes"

func init() {
	Trace = &Tracer{
		ring:   make([]*bytes.Buffer, TraceSize),
		filter: make(map[Id]struct{}),
	}
	for i := range Trace.ring {
		Trace.ring[i] = &bytes.Buffer{}
	}
}
