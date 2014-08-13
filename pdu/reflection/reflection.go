// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package reflection provides a method to validate pdu format, parse, and
// trace.
package reflection

import (
	"errors"
	"fmt"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/yab"
	"os"
	"reflect"
)

var buf *yab.Buffer

func init() {
	buf = yab.New()
	pdu.TraceUnfilter(pdu.NpduIds)
}

// Check formats the given pdu into a buffer; parses that buffer into another
// pdu; then compares the copy to the original. This returns true if
// successful. This also respectively flushes a simple or comparative pdu trace
// to Stdout or Stderr on success or failure.
func Check(a pdu.PDUer) (pass bool) {
	var err error
	id := a.Id()
	b := pdu.New(id)

	buf.Reset()
	a.Format(pdu.Version, buf)
	if e := b.Parse(buf); e != pdu.Success {
		err = pdu.Errors[e]
	} else if !reflect.DeepEqual(a, b) {
		err = errors.New("Mismatched PDUs")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		pdu.Trace(id, "A:", id, a)
		pdu.Trace(id, "B:", id, b)
		pdu.TraceFlush(os.Stderr)
	} else {
		pdu.Trace(id, id, b)
		pdu.TraceFlush(os.Stdout)
		pass = true
	}
	return
}
