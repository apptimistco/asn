// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"fmt"
	"github.com/apptimistco/asn/ack"
	"github.com/apptimistco/asn/echo"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/box"
	"github.com/apptimistco/datum"
	"github.com/apptimistco/nbo"
	"github.com/apptimistco/yab"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"
)

var (
	Diag = ioutil.Discard
)

const connTO = 200 * time.Millisecond

const (
	_ uint8 = iota
	established
	suspended
	quitting
)

type Rxer func(pdu.PDUer, *datum.Datum) error

var noopRx Rxer = func(_ pdu.PDUer, _ *datum.Datum) error { return nil }

type ASN struct {
	// Name of session prefaced to trace logs and diagnostics.
	Name string
	// PDU receivers
	rxer [pdu.NpduIds]Rxer
	// Need to lock Tx but UntilQuit is single threaded
	mutex *sync.Mutex
	// Version adapts to peer
	// State may be { undefined, established, suspended, quitting }
	version, state uint8
	// Receive data
	rxdata *datum.Datum
	// Opened/Sealed Rx/Tx Header Buffers
	orhbuf, othbuf, srhbuf, sthbuf *yab.Buffer
	// Keys to Open/Seal Header Buffers
	box *box.Box
	// Channels to interrupt Conn Read/Write
	rstop chan error
	wstop chan error
	conn  net.Conn
}

// New Apptimist Social Network Service or App.
func New(name string) *ASN {
	asn := &ASN{
		Name:    name,
		version: pdu.Version,
	}
	asn.Register(pdu.SessionPauseReqId, noopRx)
	asn.Register(pdu.SessionResumeReqId, noopRx)
	asn.mutex = new(sync.Mutex)
	asn.rxdata, _ = datum.Open("")
	asn.orhbuf = yab.New()
	asn.othbuf = yab.New()
	asn.srhbuf = yab.New()
	asn.sthbuf = yab.New()
	asn.rstop = make(chan error)
	asn.wstop = make(chan error)
	return asn
}

func (asn *ASN) Close() error {
	asn.rxdata.Close()
	asn.orhbuf.Close()
	asn.othbuf.Close()
	asn.srhbuf.Close()
	asn.sthbuf.Close()
	return nil
}

// Register a creator for the given id.
func (asn *ASN) Register(id pdu.Id, rx Rxer) {
	if id < pdu.NpduIds {
		asn.rxer[id] = rx
	}
}

// Preempt PDU Rx & Tx.
func (asn *ASN) Preempt() {
	asn.rstop <- io.ErrUnexpectedEOF
	asn.wstop <- io.ErrUnexpectedEOF
}

// Ack the given PDU Id. On an error with nil data, include the error string.
func (asn *ASN) Ack(id pdu.Id, e pdu.Err, vdata interface{}) {
	if id != pdu.AckId { // don't ack an Ack
		if e != pdu.Success && uint(e) < pdu.Nerrors {
			if vdata == nil {
				if err := pdu.Errors[e]; err != nil {
					vdata = err.Error()
				}
			}
		}
		asn.Tx(ack.NewAck(id, e), vdata)
	}
}

// RxUntilErr receives, decrypts, parses and processes ASN PDUs
// through registered receivers until and acknowledged QuitReq
// or error. This may be killed with asn.Preempt()
func (asn *ASN) UntilQuit() (err error) {
	defer func() {
		if err != nil && err != io.EOF {
			fmt.Fprintln(Diag, asn.Name, "UntilQuit:", err)
		}
	}()
Loop:
	for {
		if err = asn.rxOpen(); err != nil {
			return
		}
		pdu.Trace(pdu.RawId, asn.Name, "Rx", pdu.RawId, asn.orhbuf)
		id := pdu.ShortId
		if len(asn.orhbuf.Buf) >= 2 {
			id = pdu.NormId(asn.orhbuf.Buf[0], asn.orhbuf.Buf[1])
		}
		if id.IsErr() {
			asn.Ack(id, id.Err(), nil)
		}
		if asn.orhbuf.Buf[0] < asn.version {
			asn.version = asn.orhbuf.Buf[0]
		}
		vpdu := pdu.New(id)
		if vpdu == nil {
			asn.Ack(id, pdu.UnknownErr, nil)
			continue Loop
		}
		e := vpdu.Parse(asn.orhbuf)
		if e != pdu.Success {
			asn.Ack(id, e, nil)
			continue Loop
		}
		pdu.Trace(id, asn.Name, "Rx", id, vpdu)
		rxer := asn.rxer[id]
		switch id {
		// The do nothing cases bypass the default state check.
		default:
			if asn.state != established {
				return pdu.ErrDisestablished
			}
		case pdu.AckId:
			xack, _ := vpdu.(*ack.Ack)
			if xack.Err == pdu.Success {
				if xack.Req == pdu.SessionLoginReqId {
					asn.state = established
				}
				if xack.Req == pdu.SessionQuitReqId {
					if asn.state != quitting {
						asn.Ack(id, pdu.UnexpectedErr,
							nil)
						continue Loop
					} else if rxer == nil {
						return io.EOF
					}
				}
			}
		case pdu.EchoId:
			if rxer == nil {
				xecho, _ := vpdu.(*echo.Echo)
				if xecho.Reply == echo.Request {
					xecho.Reply = echo.Reply
					asn.Tx(xecho, asn.rxdata)
					continue Loop
				}
			}
		case pdu.SessionLoginReqId:
		case pdu.SessionPauseReqId:
			if asn.state != established {
				asn.Ack(id, pdu.UnexpectedErr, nil)
				continue Loop
			}
			asn.Ack(id, pdu.Success, nil)
		case pdu.SessionResumeReqId:
			if asn.state != suspended {
				asn.Ack(id, pdu.UnexpectedErr, nil)
				continue Loop
			}
			asn.Ack(id, pdu.Success, nil)
		case pdu.SessionQuitReqId:
			if rxer == nil {
				asn.Ack(id, pdu.Success, nil)
				return io.EOF
			}
		case pdu.UserAddReqId:
		}
		if rxer == nil {
			asn.Ack(id, pdu.UnsupportedErr, nil)
		} else if err = rxer(vpdu, asn.rxdata); err != nil {
			for i, e := range pdu.Errors {
				if e == err {
					asn.Ack(id, pdu.Err(i), nil)
					err = nil
				}
			}
			if err == nil {
				return err
			}
		}
	}
}

// rxOpen receives the PDU then opens its encrypted header.
func (asn *ASN) rxOpen() (err error) {
	var l uint64
	if _, err = (nbo.Reader{asn}).ReadNBO(&l); err != nil {
		return
	}
	hlen := l >> 48
	dlen := l & 0xffffffffffff
	if int(hlen) > cap(asn.srhbuf.Buf) {
		asn.rxdata.Reset()
		asn.rxdata.Limit(int64(dlen))
		asn.rxdata.ReadFrom(asn)
		asn.rxdata.Reset()
		err = yab.ErrTooLarge
		return
	}
	asn.srhbuf.Limit(int64(hlen))
	if _, err = asn.srhbuf.ReadFrom(asn); err != nil {
		return
	}
	if dlen > 0 {
		asn.rxdata.Reset()
		asn.rxdata.Limit(int64(dlen))
		_, err = asn.rxdata.ReadFrom(asn)
		if err != nil {
			return err
		}
	}
	asn.orhbuf.Reset()
	asn.orhbuf.Buf, err = asn.box.Open(asn.orhbuf.Buf, asn.srhbuf.Buf)
	return
}

// Read full buffer unless preempted.
func (asn *ASN) Read(b []byte) (n int, err error) {
	for i := 0; n < len(b); n += i {
		asn.conn.SetReadDeadline(time.Now().Add(connTO))
		select {
		case err = <-asn.rstop:
			return
		default:
			i, err = asn.conn.Read(b[n:])
			if err != nil {
				eto, ok := err.(net.Error)
				if !ok || !eto.Timeout() {
					return
				}
				err = nil
			}
		}
	}
	return
}

func (asn *ASN) SetBox(box *box.Box)   { asn.box = box }
func (asn *ASN) SetConn(conn net.Conn) { asn.conn = conn }

// Format, box, then send a PDU.
func (asn *ASN) Tx(vpdu pdu.PDUer, vdata interface{}) (err error) {
	asn.mutex.Lock()
	defer func() {
		asn.mutex.Unlock()
		if err != nil && err != io.EOF {
			fmt.Fprintln(Diag, asn.Name, "Tx:", err)
		}
	}()
	asn.othbuf.Reset()
	vpdu.Format(asn.version, asn.othbuf)
	id := vpdu.Id()
	switch asn.state {
	case quitting:
		return pdu.ErrUnexpected
	case suspended:
		if id != pdu.SessionResumeReqId && id != pdu.SessionQuitReqId {
			return pdu.ErrSuspended
		}
	default:
		if id != pdu.AckId &&
			id != pdu.EchoId &&
			id != pdu.UserAddReqId &&
			id != pdu.SessionLoginReqId &&
			id != pdu.SessionQuitReqId {
			return pdu.ErrUnexpected
		}
	}
	if err = asn.sealTx(vdata); err != nil {
		return
	}
	pdu.Trace(id, asn.Name, "Tx", id, vpdu)
	pdu.Trace(pdu.RawId, asn.Name, "Tx", pdu.RawId, asn.othbuf)
	switch id {
	case pdu.AckId:
		xack, _ := vpdu.(*ack.Ack)
		if xack.Err == pdu.Success {
			if xack.Req == pdu.SessionLoginReqId ||
				xack.Req == pdu.SessionResumeReqId {
				asn.state = established
			} else if xack.Req == pdu.SessionPauseReqId {
				asn.state = suspended
			}
		}
	case pdu.SessionPauseReqId:
		asn.state = suspended
	case pdu.SessionResumeReqId:
		if asn.state == suspended {
			asn.state = established
		}
	case pdu.SessionQuitReqId:
		asn.state = quitting
	}
	return
}

// sealTx seals the header then transmits the PDU.
func (asn *ASN) sealTx(vdata interface{}) (err error) {
	asn.sthbuf.Reset()
	asn.sthbuf.Buf, err = asn.box.Seal(asn.sthbuf.Buf, asn.othbuf.Buf)
	if err != nil {
		return err
	}
	l := uint64(len(asn.sthbuf.Buf)) << 48
	switch t := vdata.(type) {
	case *datum.Datum:
		l |= uint64(t.Len())
	case string:
		l |= uint64(len(t))
	case []byte:
		l |= uint64(len(t))
	}
	if _, err = (nbo.Writer{asn}).WriteNBO(l); err == nil {
		if _, err = asn.sthbuf.WriteTo(asn); err == nil {
			switch t := vdata.(type) {
			case *datum.Datum:
				_, err = t.WriteTo(asn)
			case string:
				_, err = asn.Write([]byte(t))
			case []byte:
				_, err = asn.Write(t)
			}
		}
	}
	return
}

// Write full buffer unless preempted.
func (asn *ASN) Write(b []byte) (n int, err error) {
	for i := 0; n < len(b); n += i {
		asn.conn.SetWriteDeadline(time.Now().Add(connTO))
		select {
		case err = <-asn.wstop:
			return
		default:
			i, err = asn.conn.Write(b[n:])
			if err != nil {
				eto, ok := err.(net.Error)
				if !ok || !eto.Timeout() {
					return
				}
				err = nil
			}
		}
	}
	return
}
