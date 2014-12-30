// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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
	suspended
	quitting
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
	// State may be { opened, established, suspended, quitting }
	state uint8
	// Keys to Open/Seal
	box  *Box
	RxQ  chan *PDU
	txq  chan pdubox
	conn net.Conn
	// buffers
	rxBlack, rxRed []byte
	txBlack, txRed []byte
	// Repository
	Repos *Repos
	// Ack handler map
	Acker acker
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
			RxQ:     make(chan *PDU, 4),
			txq:     make(chan pdubox, 4),
			rxBlack: make([]byte, 0, MaxSegSz),
			rxRed:   make([]byte, 0, MaxSegSz),
			txBlack: make([]byte, 0, MaxSegSz),
			txRed:   make([]byte, 0, MaxSegSz),
		}
		asn.Acker.Init()
	}
	return
}

// Del[ete] an ASN
func (asn *ASN) del() {
	if asn == nil {
		return
	}
	asn.box = nil
	close(asn.RxQ)
	close(asn.txq)
	asn.rxBlack = nil
	asn.rxRed = nil
	asn.txBlack = nil
	asn.txRed = nil
	asn.Acker.Free()
}

// Free the ASN back to pool or release it to GC if full.
func (asn *ASN) Free() {
	if asn == nil {
		return
	}
	if asn.conn != nil {
		asn.SetStateClosed()
		asn.conn.Close()
		asn.conn = nil
	}
flush: // flush queues
	for {
		select {
		case pdu := <-asn.RxQ:
			if pdu != nil {
				pdu.Free()
				pdu = nil
			}
		case pb := <-asn.txq:
			if pb.pdu != nil {
				pb.pdu.Free()
				pb.pdu = nil
				pb.box = nil
			}
		default:
			break flush
		}
	}
	asn.Name.Local = ""
	asn.Name.Remote = ""
	asn.Name.Session = ""
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
func (asn *ASN) IsSuspended() bool   { return asn.state == suspended }
func (asn *ASN) IsQuitting() bool    { return asn.state == quitting }
func (asn *ASN) IsClosed() bool      { return asn.state == closed }

// pdurx receives, decrypts and reassembles segmented PDUs on the asn.RxQ until
// error, or EOF; then sends nil through asn.RxQ when done.
func (asn *ASN) pdurx() {
	pdu := NewPDUBuf()
	defer func() {
		var err error
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
		pdu.Free()
		asn.RxQ <- nil
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			asn.Diag("pdurx", err)
		} else {
			asn.Diag("pdurx", "quit")
		}
	}()
	for {
		var l uint16
		_, err := (NBOReader{asn}).ReadNBO(&l)
		if err != nil {
			panic(err)
		}
		n := l & ^MoreFlag
		if n > MaxSegSz {
			panic(ErrTooLarge)
		}
		if pdu.File != nil && pdu.PB != nil {
			asn.Diag("oops pdu %p\n", pdu)
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
			asn.Diag("pdu.Write:", err)
			panic(err)
		}
		if (l & MoreFlag) == 0 {
			asn.Diagf("RXQ %p; len %d\n", pdu, pdu.Len())
			asn.RxQ <- pdu
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
			asn.Diagf("extend %p into %s\n", pdu, pdu.FN)
		}
	}
}

// pdutx pulls PDU from asn.txq, segments, and encrypts before sending
// through asn.conn. This stops on error or nil.
func (asn *ASN) pdutx() {
	const maxBlack = MaxSegSz - BoxOverhead
	var (
		err error
		pb  pdubox
	)
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			asn.Diag("pdutx", err)
		} else {
			asn.Diag("pdutx", "quit")
		}
	}()
	for {
		if pb = <-asn.txq; pb.pdu == nil {
			return
		}
		if err = pb.pdu.Open(); err != nil {
			return
		}
	segLoop:
		for {
			n := pb.pdu.Len()
			if n == 0 {
				break segLoop
			}
			if n > maxBlack {
				n = maxBlack
			}
			asn.txBlack = asn.txBlack[:n]
			if _, err = pb.pdu.Read(asn.txBlack); err != nil {
				break segLoop
			}
			asn.txRed = asn.txRed[:0]
			var b []byte
			b, err = pb.box.Seal(asn.txRed, asn.txBlack)
			if err != nil {
				break segLoop
			}
			l := uint16(len(b))
			if pb.pdu.Len() > 0 {
				l |= MoreFlag
			}
			if _, err = (NBOWriter{asn}).WriteNBO(l); err != nil {
				break segLoop
			}
			if _, err = asn.Write(b); err != nil {
				break segLoop
			}
			asn.Diagf("tx pdu %p; len %d\n", pb.pdu, l & ^MoreFlag)
		}
		pb.pdu.Free()
		pb.pdu = nil
		pb.box = nil
		if err != nil {
			return
		}
		if asn.IsQuitting() {
			v := Version(asn.txBlack[0])
			id := Id(asn.txBlack[1])
			if id.Internal(v); id == AckReqId {
				return
			}
		}
	}
}

// Read full buffer from asn.conn unless preempted with state == closed.
func (asn *ASN) Read(b []byte) (n int, err error) {
	for i := 0; n < len(b); n += i {
		if asn.IsClosed() {
			err = io.EOF
			break
		}
		asn.conn.SetReadDeadline(time.Now().Add(ConnTO))
		i, err = asn.conn.Read(b[n:])
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

func (asn *ASN) SetBox(box *Box) { asn.box = box }

// SetConn[ection] socket and start Go routines for PDU Q's
func (asn *ASN) SetConn(conn net.Conn) {
	asn.conn = conn
	asn.SetStateOpened()
	go asn.pdurx()
	go asn.pdutx()
}

func (asn *ASN) SetStateOpened()      { asn.state = opened }
func (asn *ASN) SetStateProvisional() { asn.state = provisional }
func (asn *ASN) SetStateEstablished() { asn.state = established }
func (asn *ASN) SetStateSuspended()   { asn.state = suspended }
func (asn *ASN) SetStateQuitting()    { asn.state = quitting }
func (asn *ASN) SetStateClosed()      { asn.state = closed }

func (asn *ASN) SetVersion(v Version) {
	if v < Latest {
		asn.version = v
	}
}

// Queue PDU for segmentation, encryption and transmission
func (asn *ASN) Tx(pdu *PDU) {
	if pdu.FN != "" {
		if pdu.File != nil {
			asn.Diag("tx", pdu.FN, "size", pdu.Size())
		} else {
			asn.Diag("tx", pdu.FN)
		}
	} else {
		asn.Diagf("tx %x\n", pdu.PB.Bytes())
	}
	asn.txq <- pdubox{pdu: pdu, box: asn.box}
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
