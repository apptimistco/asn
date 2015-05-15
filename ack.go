// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/mutex"
)

// AckerF is an Acknowledgment handler for the given request and trailing Ack
// data.
type AckerF func(Req, error, *PDU) error

type acker struct {
	mutex.Mutex
	m map[Req]AckerF
}

func (acker *acker) Init() {
	acker.Mutex.Set("acker")
	if acker.m == nil {
		acker.m = make(map[Req]AckerF)
	}
}

func (acker *acker) Reset() {
	for k, _ := range acker.m {
		acker.m[k] = nil
	}
}

// Map a handler to the given request.
func (acker *acker) Map(req Req, f AckerF) {
	acker.Lock()
	defer acker.Unlock()
	acker.m[req] = f
}

// UnMap a handler to the given request.
func (acker *acker) UnMap(req Req) {
	acker.Lock()
	defer acker.Unlock()
	acker.m[req] = nil
}

// Rx processes recieved acks with registered handlers.
func (asn *asn) AckerRx(pdu *PDU) (err error) {
	var req Req
	if _, err = req.ReadFrom(pdu); err != nil {
		return
	}
	if _, err = (NBOReader{pdu}).ReadNBO(&asn.time.in); err != nil {
		return
	}
	if err = asn.ParseAckError(pdu); err == nil {
		asn.Trace(debug.Id(AckReqId), "rx", req, "ack")
	} else {
		asn.Trace(debug.Id(AckReqId), "rx", req, "nack", err)
	}
	asn.acker.Lock()
	f, ok := asn.acker.m[req]
	asn.acker.Unlock()
	if ok && f != nil {
		err = f(req, err, pdu)
	} else {
		pdu.Free()
		err = errors.New("unregistered Ack request")
		asn.Diag(err)
	}
	return
}

// Ack the given requester. If the argument is an error, the associate code is
// used in the negative reply with the error string. Otherwise, it's a
// successful Ack with any subsequent args appended as data.
// Only use this for page sized acks, anything larger should use
// NewAckSuccessPDUFile
func (asn *asn) Ack(req Req, argv ...interface{}) {
	var err error
	if len(argv) == 1 {
		switch t := argv[0].(type) {
		case *PDU:
			asn.Tx(t)
			return
		case error:
			err = t
			argv = argv[1:]
		case nil:
			if len(argv) > 1 {
				argv = argv[1:]
			} else {
				argv = argv[:0]
			}
		}
	}
	ack := NewPDUBuf()
	v := asn.version
	v.WriteTo(ack)
	AckReqId.Version(v).WriteTo(ack)
	req.WriteTo(ack)
	(NBOWriter{ack}).WriteNBO(asn.time.out)
	if err != nil {
		asn.Trace(debug.Id(AckReqId), "tx", req, "nack", err)
		asn.Log(req, "nack", err)
		ErrFromError(err).Version(v).WriteTo(ack)
		if len(argv) > 0 {
			AckOut(ack, argv...)
		} else {
			ack.Write([]byte(err.Error()))
		}
	} else {
		asn.Trace(debug.Id(AckReqId), "tx", req, "ack")
		asn.Log(req, "ack")
		Success.Version(v).WriteTo(ack)
		AckOut(ack, argv...)
	}
	asn.Tx(ack)
}

// AckOut is used by the above asn.Ack to write Ack content to the given
// writer. It is also used by asnsrv to print Ack content to Stdout.
func AckOut(w io.Writer, argv ...interface{}) {
	for _, v := range argv {
		switch t := v.(type) {
		case *PDU:
			if err := t.Open(); err == nil {
				var (
					v   Version
					id  Id
					req Req
					rxt time.Time
					ec  Err
				)
				v.ReadFrom(t)
				id.ReadFrom(t)
				req.ReadFrom(t)
				(NBOReader{t}).ReadNBO(&rxt)
				ec.ReadFrom(t)
				if ec != Success {
					w.Write([]byte("Error: "))
				}
				t.WriteTo(w)
			}
			t.Free()
		case WriteToer:
			t.WriteTo(w)
		case io.Reader:
			io.Copy(w, t)
		case []byte:
			w.Write(t)
		case string:
			io.WriteString(w, t)
		case func(io.Writer):
			t(w)
		case []*os.File:
			for i, f := range t {
				io.Copy(w, f)
				f.Close()
				t[i] = nil
			}
		case *Sum:
			w.Write([]byte(t.String()))
			w.Write([]byte("\n"))
		}
	}
}

// NewAckSuccessPDUFile creates a temp file preloaded with the asn success ack
// header and ready to write success data.
func (asn *asn) NewAckSuccessPDUFile(req Req) (ack *PDU, err error) {
	f := asn.repos.tmp.New()
	ack = NewPDUFile(f)
	f = nil
	v := asn.version
	v.WriteTo(ack)
	AckReqId.Version(v).WriteTo(ack)
	req.WriteTo(ack)
	(NBOWriter{ack}).WriteNBO(asn.time.out)
	Success.Version(v).WriteTo(ack)
	asn.Log(req, "ack")
	return
}

// ParseAckError returns a GO error, if any, derrived from the Ack and
// returns nil if Ack indicates success.
func (asn *asn) ParseAckError(ack *PDU) (err error) {
	var e Err
	e.ReadFrom(ack)
	e.Internal(asn.Version())
	err = e.ErrToError()
	if err == ErrFailure {
		var b [256]byte
		n, _ := ack.Read(b[:])
		err = errors.New(string(b[:n]))
	}
	return
}
