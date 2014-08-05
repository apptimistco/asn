// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"encoding/binary"
	"github.com/apptimistco/asn/ack"
	"github.com/apptimistco/asn/echo"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/box"
	"io"
	"net"
	"sync"
	"time"
)

const connTO = 200 * time.Millisecond

const (
	_ uint8 = iota
	established
	suspended
	quitting
)

type Rxer func(pdu.PDUer, []byte) error

var noopRx Rxer = func(_ pdu.PDUer, _ []byte) error { return nil }

type ASN struct {
	name    string
	rxer    [pdu.NpduIds]Rxer
	black   blackPDU
	version uint8
	state   uint8
}

// New Apptimist Social Network Service or App.
func New(name string) *ASN {
	asn := &ASN{
		name:    name,
		version: pdu.Version,
	}
	asn.Register(pdu.SessionPauseReqId, noopRx)
	asn.Register(pdu.SessionResumeReqId, noopRx)
	asn.black.red.rstop = make(chan error)
	asn.black.red.wstop = make(chan error)
	asn.black.red.rmutex = new(sync.Mutex)
	asn.black.red.wmutex = new(sync.Mutex)
	return asn
}

// Register a creator for the given id.
func (asn *ASN) Register(id pdu.Id, rx Rxer) {
	if id < pdu.NpduIds {
		asn.rxer[id] = rx
	}
}

// Preempt PDU Rx & Tx.
func (asn *ASN) Preempt() {
	asn.black.red.rstop <- io.EOF
	asn.black.red.wstop <- io.EOF
}

func (asn *ASN) Ack(id pdu.Id, e pdu.Err, data []byte) {
	if id != pdu.AckId { // don't ack an Ack
		if data == nil {
			data = []byte{}
			if e != pdu.Success && uint(e) < pdu.Nerrors {
				err := pdu.Errors[e]
				if err != nil {
					data = []byte(err.Error())
				}
			}
		}
		asn.Tx(ack.NewAck(id, e), data)
	}
}

// RxUntilErr receives, decrypts, parses and processes ASN PDUs
// through registered receivers until and acknowledged QuitReq
// or error. This may be killed with asn.Preempt()
func (asn *ASN) RxUntilErr() error {
Loop:
	for {
		header, eData, err := asn.black.rx()
		if err != nil {
			return err
		}
		pdu.Trace(asn.name, "Rx", pdu.RawId, pdu.Raw(header), eData)
		if header[0] < asn.version {
			asn.version = header[0]
		}
		id := pdu.ShortId
		if len(header) >= 2 {
			id = pdu.NormId(header[0], header[1])
		}
		if id.IsErr() {
			asn.Ack(id, id.Err(), nil)
		}
		vpdu := pdu.New(id)
		if vpdu == nil {
			asn.Ack(id, pdu.UnknownErr, nil)
			continue Loop
		}
		e := vpdu.Parse(header)
		if e != pdu.Success {
			asn.Ack(id, e, nil)
			continue Loop
		}
		pdu.Trace(asn.name, "Rx", id, vpdu, eData)
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
					asn.Tx(xecho, eData)
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
		} else if err = rxer(vpdu, eData); err != nil {
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

func (asn *ASN) SetBox(box *box.Box)   { asn.black.box = box }
func (asn *ASN) SetConn(conn net.Conn) { asn.black.red.conn = conn }

// Format, box, then send a PDU.
func (asn *ASN) Tx(vpdu pdu.PDUer, eData []byte) error {
	header := vpdu.Format(asn.version)
	defer func() {
		header = header[:0]
	}()
	id := pdu.NormId(header[0], header[1])
	switch asn.state {
	case quitting:
		return pdu.ErrUnexpected
	case suspended:
		if id != pdu.SessionResumeReqId &&
			id != pdu.SessionQuitReqId {
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
	if err := asn.black.tx(header, eData); err != nil {
		return err
	}
	pdu.Trace(asn.name, "Tx", id, vpdu, eData)
	pdu.Trace(asn.name, "Tx", pdu.RawId, pdu.Raw(header), eData)
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
	return nil
}

type blackPDU struct {
	box *box.Box
	red redPDU
}

// Read encrypted header and data then decrypt header.
func (black blackPDU) rx() (header, eData []byte, err error) {
	eHeader, eData, err := black.red.rx()
	if err != nil {
		return nil, nil, err
	}
	header, err = black.box.Open(nil, eHeader)
	if err != nil {
		return nil, nil, err
	}
	return
}

// Encrypt header then transmit PDU.
func (black blackPDU) tx(header, eData []byte) error {
	eHeader, err := black.box.Seal(nil, header)
	if err != nil {
		return err
	}
	return black.red.tx(eHeader, eData)
}

type redPDU struct {
	rstop, wstop   chan error
	rmutex, wmutex *sync.Mutex

	conn net.Conn
}

// Received encrypted header and data prefaced by respective lenghts.
func (red redPDU) rx() (eHeader, eData []byte, err error) {
	red.rmutex.Lock()
	defer red.rmutex.Unlock()
	red.conn.SetReadDeadline(time.Now().Add(connTO))
	lbuf := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	err = red.read(lbuf)
	if err != nil {
		return nil, nil, err
	}
	hlen := binary.BigEndian.Uint32(lbuf[0:4])
	dlen := binary.BigEndian.Uint32(lbuf[4:])
	eHeader = make([]byte, hlen)
	if err = red.read(eHeader); err != nil {
		eHeader = eHeader[:0]
		return nil, nil, err
	}
	if dlen > 0 {
		eData = make([]byte, dlen)
		if err = red.read(eData); err != nil {
			eHeader = eHeader[:0]
			eData = eData[:0]
			return nil, nil, err
		}
	}
	return
}

// Transmit encrypted header and data prefaced by respective lenghts.
func (red redPDU) tx(eHeader, eData []byte) error {
	red.wmutex.Lock()
	defer red.wmutex.Unlock()
	red.conn.SetWriteDeadline(time.Now().Add(connTO))
	lbuf := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(lbuf[0:4], uint32(len(eHeader)))
	binary.BigEndian.PutUint32(lbuf[4:], uint32(len(eData)))
	err := red.write(lbuf)
	if err == nil {
		if err = red.write(eHeader); err == nil {
			if len(eData) > 0 {
				err = red.write(eData)
			}
		}
	}
	return err
}

// Read full buffer unless preempted.
func (red redPDU) read(b []byte) (err error) {
	for i, n := 0, 0; i < len(b); i += n {
		select {
		case err = <-red.rstop:
			return
		default:
			n, err = red.conn.Read(b[i:])
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

// Write full buffer unless preempted.
func (red redPDU) write(b []byte) (err error) {
	for i, n := 0, 0; i < len(b); i += n {
		select {
		case err = <-red.wstop:
			return
		default:
			n, err = red.conn.Write(b[i:])
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
