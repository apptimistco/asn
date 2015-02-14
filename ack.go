// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// AckerF is an Acknowledgment handler for the given request and trailing Ack
// data.
type AckerF func(Requester, *PDU) error

type acker struct {
	mutex *sync.Mutex
	fmap  map[Requester]AckerF
}

// Init an ASN callback map
func (acker *acker) Init() {
	acker.mutex = new(sync.Mutex)
	acker.fmap = make(map[Requester]AckerF)
}

// Free the ASN callback map
func (acker *acker) Free() {
	for k, _ := range acker.fmap {
		acker.fmap[k] = nil
	}
	acker.fmap = nil
	acker.mutex = nil
}

// Map a handler to the given request.
func (acker *acker) Map(req Requester, f AckerF) {
	acker.mutex.Lock()
	defer acker.mutex.Unlock()
	acker.fmap[req] = f
}

// UnMap a handler to the given request.
func (acker *acker) UnMap(req Requester) {
	acker.mutex.Lock()
	defer acker.mutex.Unlock()
	acker.fmap[req] = nil
}

// Rx processes recieved acks with registered handlers.
func (asn *ASN) AckerRx(pdu *PDU) (err error) {
	var req Requester
	if _, err = req.ReadFrom(pdu); err != nil {
		return
	}
	if _, err = (NBOReader{pdu}).ReadNBO(&asn.Time.In); err != nil {
		return
	}
	asn.Acker.mutex.Lock()
	f := asn.Acker.fmap[req]
	asn.Acker.mutex.Unlock()
	if f == nil {
		pdu.Free()
		err = errors.New("unregistered Ack request")
	} else {
		err = f(req, pdu)
	}
	return
}

// Ack the given requester. If the argument is an error, the associate code is
// used in the negative reply with the error string. Otherwise, it's a
// successful Ack with any subsequent args appended as data.
// Only use this for page sized acks, anything larger should use
// NewAckSuccessPDUFile
func (asn *ASN) Ack(req Requester, argv ...interface{}) {
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
			argv = argv[1:]
		}
	}
	ack := NewPDUBuf()
	v := asn.version
	v.WriteTo(ack)
	AckReqId.Version(v).WriteTo(ack)
	req.WriteTo(ack)
	(NBOWriter{ack}).WriteNBO(asn.Time.Out)
	if err != nil {
		asn.Trace("tx", AckReqId, req, err)
		asn.Diag("nack", err)
		ErrFromError(err).Version(v).WriteTo(ack)
		if len(argv) > 0 {
			AckOut(ack, argv...)
		} else {
			ack.Write([]byte(err.Error()))
		}
	} else {
		asn.Trace("tx", AckReqId, req, Success)
		Success.Version(v).WriteTo(ack)
		AckOut(ack, argv...)
		asn.Diag("ack")
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
					req Requester
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
		case *bytes.Buffer:
			t.WriteTo(w)
		case []byte:
			w.Write(t)
		case string:
			w.Write([]byte(t))
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
func (asn *ASN) NewAckSuccessPDUFile(req Requester) (ack *PDU, err error) {
	f, err := asn.Repos.Tmp.NewFile()
	if err != nil {
		return
	}
	ack = NewPDUFile(f)
	f = nil
	v := asn.version
	v.WriteTo(ack)
	AckReqId.Version(v).WriteTo(ack)
	req.WriteTo(ack)
	(NBOWriter{ack}).WriteNBO(asn.Time.Out)
	Success.Version(v).WriteTo(ack)
	return
}

// ParseAckError returns a GO error, if any, derrived from the Ack and
// returns nil if Ack indicates success.
func (asn *ASN) ParseAckError(ack *PDU) (err error) {
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
