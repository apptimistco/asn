// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"fmt"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/pdu/ack"
	"github.com/apptimistco/box"
	"github.com/apptimistco/datum"
	"github.com/apptimistco/nbo"
	"github.com/apptimistco/yab"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	Diag = ioutil.Discard
	pool chan *ASN
)

const connTO = 200 * time.Millisecond

const (
	undefined uint8 = iota
	established
	suspended
	quitting
)

func init() { pool = make(chan *ASN, 16) }

type ASN struct {
	// Name of session prefaced to trace logs and diagnostics.
	Name string
	// Need to lock Tx but UntilQuit is single threaded
	mutex *sync.Mutex
	// Version adapts to peer
	version uint8
	// State may be { undefined, established, suspended, quitting }
	state uint8
	// Keys to Open/Seal Header Buffers
	box *box.Box
	// Channels to interrupt Conn Read/Write
	rstop chan error
	wstop chan error
	conn  net.Conn
}

// Del[ete] an ASN
func Del(a *ASN) {
	if a == nil {
		return
	}
	a.mutex = nil
	a.box = nil
	close(a.rstop)
	close(a.wstop)
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
}

// Flush the ASN pool.
func Flush() {
	for {
		select {
		case a := <-pool:
			Del(a)
		default:
			return
		}
	}
}

// New Apptimist Social Network Service or App.
func New(name string) *ASN {
	return &ASN{
		Name:    name,
		version: pdu.Version,
		mutex:   &sync.Mutex{},
		rstop:   make(chan error),
		wstop:   make(chan error),
	}
}

// Pull an ASN from pool or create a new one if necessary.
func Pull() (a *ASN) {
	select {
	case a = <-pool:
	default:
		a = New("unnamed")
	}
	return
}

// Push the double-indirect ASN back to pool or release it to GC if full;
// then nil its reference.
func Push(p **ASN) {
	a := *p
	if a == nil {
		return
	}
	// flush any stop signals
	for _, ch := range [2]chan error{a.rstop, a.wstop} {
	stopLoop:
		for {
			select {
			case <-ch:
			default:
				break stopLoop
			}
		}
	}
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
	a.Name = ""
	a.state = undefined
	select {
	case pool <- a:
	default:
		Del(a)
	}
	*p = nil
}

// Preempt PDU Rx & Tx.
func (asn *ASN) Preempt() {
	asn.rstop <- io.ErrUnexpectedEOF
	asn.wstop <- io.ErrUnexpectedEOF
}

// Ack the given PDU Id. On an error with nil data, include the error string.
func (asn *ASN) Ack(id pdu.Id, e pdu.Err, vdata interface{}) error {
	if id != pdu.AckId { // don't ack an Ack
		if e != pdu.Success && uint(e) < pdu.Nerrors {
			if vdata == nil {
				if err := pdu.Errors[e]; err != nil {
					vdata = err.Error()
				}
			}
		}
		return asn.Tx(ack.NewAck(id, e), vdata)
	}
	return nil
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

// Rx receives, decrypts, parses and returns the ASN PDU with its data, if any.
// This also performs state transitions per ASN protocol.
func (asn *ASN) Rx() (vpdu pdu.PDUer, d *datum.Datum, err error) {
	var h *yab.Buffer
	for {
		h, d, err = asn.rxopen()
		if err != nil {
			break
		}
		pdu.Trace(pdu.RawId, asn.Name, "Rx", pdu.RawId, h)
		id := pdu.ShortId
		if len(h.Buf) >= 2 {
			id = pdu.NormId(h.Buf[0], h.Buf[1])
		}
		if id.IsErr() {
			asn.Ack(id, id.Err(), nil)
			goto again
		}
		if h.Buf[0] < asn.version {
			asn.version = h.Buf[0]
		}
		vpdu = pdu.New(id)
		if vpdu == nil {
			asn.Ack(id, pdu.UnknownErr, nil)
			goto again
		}
		if e := vpdu.Parse(h); e != pdu.Success {
			asn.Ack(id, e, nil)
			goto again
		}
		pdu.Trace(id, asn.Name, "Rx", id, vpdu)
		switch id {
		// The do nothing cases bypass the default state check.
		default:
			if asn.state != established {
				err = pdu.ErrDisestablished
			}
		case pdu.AckId:
			switch xack, _ := vpdu.(*ack.Ack); xack.Req {
			case pdu.SessionLoginReqId:
				if xack.Err == pdu.Success {
					asn.state = established
				} else if uint(xack.Err) < pdu.Nerrors {
					err = pdu.Errors[xack.Err]
				} else {
					err = pdu.Errors[pdu.DeniedErr]
				}
			case pdu.SessionQuitReqId:
				if asn.state != quitting {
					goto again
				}
			}
		case pdu.SessionLoginReqId:
		case pdu.SessionPauseReqId:
			if asn.state != established {
				asn.Ack(id, pdu.UnexpectedErr, nil)
				goto again
			}
			asn.Ack(id, pdu.Success, nil)
		case pdu.SessionResumeReqId:
			if asn.state != suspended {
				asn.Ack(id, pdu.UnexpectedErr, nil)
				goto again
			}
			asn.Ack(id, pdu.Success, nil)
		case pdu.SessionQuitReqId:
			asn.Ack(id, pdu.Success, nil)
			err = io.EOF
		case pdu.UserAddReqId:
		}
		break
	again:
		yab.Push(&h)
		datum.Push(&d)
	}
	yab.Push(&h)
	if err != nil {
		datum.Push(&d)
	}
	return
}

// rxopen receives the PDU then opens its encrypted header.
func (asn *ASN) rxopen() (h *yab.Buffer, d *datum.Datum, err error) {
	var l uint64
	if _, err = (nbo.Reader{asn}).ReadNBO(&l); err != nil {
		return
	}
	hlen := l >> 48
	dlen := l & 0xffffffffffff
	redh := yab.Pull()
	defer yab.Push(&redh)
	redh.Limit(int64(hlen))
	if int(hlen) > cap(redh.Buf) {
		err = yab.ErrTooLarge
		return
	}
	if _, err = redh.ReadFrom(asn); err != nil {
		return
	}
	if dlen > 0 {
		d = datum.Pull()
		d.Limit(int64(dlen))
		_, err = d.ReadFrom(asn)
		if err != nil {
			return
		}
	}
	h = yab.Pull()
	h.Buf, err = asn.box.Open(h.Buf, redh.Buf)
	return
}

func (asn *ASN) SetBox(box *box.Box)   { asn.box = box }
func (asn *ASN) SetConn(conn net.Conn) { asn.conn = conn }

// Format, box, then send a PDU.
func (asn *ASN) Tx(vpdu pdu.PDUer, vdata interface{}) (err error) {
	h := yab.Pull()
	asn.mutex.Lock()
	defer func() {
		asn.mutex.Unlock()
		yab.Push(&h)
		if err != nil && err != io.EOF {
			fmt.Fprintln(Diag, asn.Name, "Tx:", err)
		}
	}()
	vpdu.Format(asn.version, h)
	id := vpdu.Id()
	switch asn.state {
	case established:
	case quitting:
		return pdu.ErrUnexpected
	case suspended:
		if id != pdu.SessionResumeReqId && id != pdu.SessionQuitReqId {
			return pdu.ErrSuspended
		}
	default:
		if id != pdu.AckId &&
			id != pdu.UserAddReqId &&
			id != pdu.SessionLoginReqId &&
			id != pdu.SessionQuitReqId {
			return pdu.ErrUnexpected
		}
	}
	if err = asn.sealTx(h, vdata); err != nil {
		return
	}
	pdu.Trace(id, asn.Name, "Tx", id, vpdu)
	pdu.Trace(pdu.RawId, asn.Name, "Tx", pdu.RawId, h)
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
func (asn *ASN) sealTx(h *yab.Buffer, vdata interface{}) (err error) {
	redh := yab.Pull()
	defer yab.Push(&redh)
	redh.Buf, err = asn.box.Seal(redh.Buf, h.Buf)
	if err != nil {
		return err
	}
	l := uint64(len(redh.Buf)) << 48
	switch t := vdata.(type) {
	case *datum.Datum:
		l |= uint64(t.Len())
	case string:
		l |= uint64(len(t))
	case []byte:
		l |= uint64(len(t))
	}
	if _, err = (nbo.Writer{asn}).WriteNBO(l); err == nil {
		if _, err = redh.WriteTo(asn); err == nil {
			switch t := vdata.(type) {
			case *datum.Datum:
				_, err = t.WriteTo(asn)
				datum.Push(&t)
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

// UrlPathSearch looks for the given file in this order.
//	path		return
//	/foo.bar	foo.bar
//	/foo/bar	foo/bar if foo/ exists; otherwise
//			/foo/bar
func UrlPathSearch(path string) string {
	dir := filepath.Dir(path)
	if dir == "/" {
		return filepath.Base(path)
	} else {
		if f, err := os.Open(dir[1:]); err == nil {
			f.Close()
			return path[1:]
		}
	}
	return path
}
