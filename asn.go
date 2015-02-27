// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	ConnTO   = 200 * time.Millisecond
	MaxSegSz = 4096
	MoreFlag = uint16(1 << 15)
)

const (
	opened uint8 = iota
	provisional
	established
	closed
)

var asnPool chan *ASN
var ErrTooLarge = errors.New("exceeds MaxSegSz")

func init() { asnPool = make(chan *ASN, 16) }

// N is a wrapper with a pointer receiver method to sum results of Read,
// ReadFrom, Write and WriteTo signatures.
type N int64

// Plus adds int or int64 results to pointer receiver.
func (n *N) Plus(v interface{}, err error) error {
	if i, ok := v.(int); ok {
		*n += N(i)
	} else if x, ok := v.(int64); ok {
		*n += N(x)
	}
	return err
}

// Pair box and pdu to support reset of box after Ack of Login
type pdubox struct {
	pdu *PDU
	box *Box
}

type ASN struct {
	// Names of session that's prefaced to trace logs and diagnostics
	Name struct {
		Local, Remote, Session string
	}
	// Version adapts to peer
	version Version
	// State may be { opened, provisional, established, closed }
	state uint8
	// Keys to Open/Seal
	box *Box
	Go  struct {
		Rx struct {
			C chan *PDU
			X bool // true on exit of GoRx
		}
		Tx struct {
			C chan pdubox
			X bool // true on exit of GoTx
		}
	}
	conn net.Conn
	// buffers
	rxBlack, rxRed []byte
	txBlack, txRed []byte
	// Repository
	Repos *Repos
	// Ack handler map
	Acker acker
	Time  struct {
		In, Out time.Time
	}
}

// Flush ASN pool.
func FlushASN() {
	for {
		select {
		case asn := <-asnPool:
			asn.del()
		default:
			return
		}
	}
}

// Pull an ASN from pool or create a new one if necessary.
func NewASN() (asn *ASN) {
	select {
	case asn = <-asnPool:
	default:
		asn = &ASN{
			version: Latest,
			rxBlack: make([]byte, 0, MaxSegSz),
			rxRed:   make([]byte, 0, MaxSegSz),
			txBlack: make([]byte, 0, MaxSegSz),
			txRed:   make([]byte, 0, MaxSegSz),
		}
	}
	asn.Go.Rx.C = make(chan *PDU, 4)
	asn.Go.Tx.C = make(chan pdubox, 4)
	asn.Go.Rx.X = false
	asn.Go.Tx.X = false
	asn.Acker.Init()
	return
}

// Del[ete] an ASN
func (asn *ASN) del() {
	if asn == nil {
		return
	}
	asn.box = nil
	asn.rxBlack = nil
	asn.rxRed = nil
	asn.txBlack = nil
	asn.txRed = nil
}

// Free the ASN back to pool or release it to GC if full.
func (asn *ASN) Free() {
	if asn == nil {
		return
	}
	if asn.conn != nil {
		if !asn.IsClosed() {
			asn.SetStateClosed()
			asn.conn.Close()
		}
		asn.conn = nil
	}
	asn.Name.Local = ""
	asn.Name.Remote = ""
	asn.Name.Session = ""
	asn.Acker.Free()
	select {
	case asnPool <- asn:
	default:
		asn.del()
	}
	asn = nil
}

func (asn *ASN) Conn() net.Conn      { return asn.conn }
func (asn *ASN) IsOpened() bool      { return asn.state == opened }
func (asn *ASN) IsProvisional() bool { return asn.state == provisional }
func (asn *ASN) IsEstablished() bool { return asn.state == established }
func (asn *ASN) IsClosed() bool      { return asn.state == closed }

func (asn *ASN) NameSession() {
	asn.Name.Session = asn.Name.Local + "(" + asn.Name.Remote + ")"
}

// GoRx receives, decrypts and reassembles segmented PDUs on the asn.Rx.Q
// until error, or EOF; then closes asn.Rx.Q when done.
func (asn *ASN) GoRx() {
	pdu := NewPDUBuf()
	defer func() {
		if r := recover(); r != nil {
			err := r.(error)
			if err != io.EOF || !asn.IsClosed() {
				Diag.Output(4, asn.Name.Session+" "+
					err.Error())
			}
		}
		pdu.Free()
		close(asn.Go.Rx.C)
		asn.Go.Rx.X = true
	}()
	for {
		l := uint16(0)
		if pdu.File != nil && pdu.PB != nil {
			panic(os.ErrInvalid)
		}
		_, err := (NBOReader{asn}).ReadNBO(&l)
		if err != nil {
			panic(err)
		}
		n := l & ^MoreFlag
		if n > MaxSegSz {
			panic(ErrTooLarge)
		}
		if n == 0 {
			panic(os.ErrInvalid)
		}
		asn.rxRed = asn.rxRed[:0]
		_, err = asn.Read(asn.rxRed[:n])
		if err != nil {
			panic(err)
		}
		asn.rxBlack = asn.rxBlack[:0]
		b, err := asn.box.Open(asn.rxBlack[:], asn.rxRed[:n])
		if err != nil {
			panic(err)
		}
		_, err = pdu.Write(b)
		if err != nil {
			panic(err)
		}
		if (l & MoreFlag) == 0 {
			// asn.Diagf("RXQ %p; len %d\n", pdu, pdu.Len())
			asn.Go.Rx.C <- pdu
			pdu = NewPDUBuf()
		} else if pdu.PB != nil {
			pdu.File, err = asn.Repos.Tmp.NewFile()
			if err != nil {
				panic(err)
			}
			pdu.FN = pdu.File.Name()
			pdu.File.Write(pdu.PB.Bytes())
			pdu.PB.Free()
			pdu.PB = nil
			// asn.Diagf("extend %p into %s\n", pdu, pdu.FN)
		}
	}
}

// GoTx pulls PDU from a channel, segments, and encrypts before sending through
// asn.conn. This stops and closes the connection on error or closed channel.
func (asn *ASN) GoTx() {
	const maxBlack = MaxSegSz - BoxOverhead
	defer func() {
		if r := recover(); r != nil {
			err := r.(error)
			Diag.Output(4, asn.Name.Session+" "+err.Error())
		}
		if asn.conn != nil {
			asn.SetStateClosed()
			asn.conn.Close()
		}
		asn.Go.Tx.X = true
	}()
	for {
		pb, open := <-asn.Go.Tx.C
		if !open {
			asn.Diag("quit pdutx")
			runtime.Goexit()
		}
		if err := pb.pdu.Open(); err != nil {
			panic(err)
		}
		for n := pb.pdu.Len(); n > 0; n = pb.pdu.Len() {
			if n > maxBlack {
				n = maxBlack
			}
			asn.txBlack = asn.txBlack[:n]
			if _, err := pb.pdu.Read(asn.txBlack); err != nil {
				panic(err)
			}
			asn.txRed = asn.txRed[:0]
			b, err := pb.box.Seal(asn.txRed, asn.txBlack)
			if err != nil {
				panic(err)
			}
			l := uint16(len(b))
			if pb.pdu.Len() > 0 {
				l |= MoreFlag
			}
			if _, err = (NBOWriter{asn}).WriteNBO(l); err != nil {
				panic(err)
			}
			if _, err = asn.Write(b); err != nil {
				panic(err)
			}
			// asn.Diagf("pdutx %p; len %d\n", pb.pdu, l & ^MoreFlag)
		}
		pb.pdu.Free()
		pb.pdu = nil
		pb.box = nil
	}
}

// Read full buffer from asn.conn unless preempted with state == closed.
func (asn *ASN) Read(b []byte) (n int, err error) {
	for i := 0; n < len(b); n += i {
		asn.conn.SetReadDeadline(time.Now().Add(ConnTO))
		i, err = asn.conn.Read(b[n:])
		if err != nil {
			if asn.IsClosed() {
				err = io.EOF
				break
			}
			eto, ok := err.(net.Error)
			if !ok || !eto.Timeout() {
				break
			}
			err = nil
		}
	}
	return
}

func (asn *ASN) SetBox(box *Box) { asn.box = box }

// SetConn[ection] socket and start Go routines for PDU Q's
func (asn *ASN) SetConn(conn net.Conn) {
	asn.conn = conn
	asn.SetStateOpened()
	go asn.GoRx()
	go asn.GoTx()
}

func (asn *ASN) SetStateOpened()      { asn.state = opened }
func (asn *ASN) SetStateProvisional() { asn.state = provisional }
func (asn *ASN) SetStateEstablished() { asn.state = established }
func (asn *ASN) SetStateClosed()      { asn.state = closed }

func (asn *ASN) SetVersion(v Version) {
	if v < Latest {
		asn.version = v
	}
}

// Queue PDU for segmentation, encryption and transmission
func (asn *ASN) Tx(pdu *PDU) {
	if asn == nil {
		Diag.Output(2, "tried to Tx on freed ASN")
		return
	}
	if asn.IsClosed() {
		Diag.Output(2, "tried to Tx on closed ASN")
		return
	}
	asn.Go.Tx.C <- pdubox{pdu: pdu, box: asn.box}
}

// Version steps down to the peer.
func (asn *ASN) Version() Version { return asn.version }

// Write full buffer unless preempted byt Closed state.
func (asn *ASN) Write(b []byte) (n int, err error) {
	for i := 0; n < len(b); n += i {
		if asn.IsClosed() {
			err = io.EOF
			break
		}
		asn.conn.SetWriteDeadline(time.Now().Add(ConnTO))
		i, err = asn.conn.Write(b[n:])
		if err != nil {
			eto, ok := err.(net.Error)
			if !ok || !eto.Timeout() {
				break
			}
			err = nil
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
