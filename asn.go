// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"errors"
	"github.com/apptimistco/box"
	"github.com/apptimistco/nbo"
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

func init() { asnPool = make(chan *ASN, 16) }

// Pair box and pdu to support reset of box after Ack of Login
type pdubox struct {
	pdu *PDU
	box *box.Box
}

type ASN struct {
	// Name of session that's prefaced to trace logs and diagnostics
	Name string
	// Version adapts to peer
	version Version
	// State may be { opened, established, suspended, quitting }
	state uint8
	// Keys to Open/Seal
	box  *box.Box
	RxQ  chan *PDU
	txq  chan pdubox
	conn net.Conn
	// buffers
	rxBlack, rxRed []byte
	txBlack, txRed []byte
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
			Name:    "unnamed",
			version: Latest,
			RxQ:     make(chan *PDU, 4),
			txq:     make(chan pdubox, 4),
			rxBlack: make([]byte, 0, MaxSegSz),
			rxRed:   make([]byte, 0, MaxSegSz),
			txBlack: make([]byte, 0, MaxSegSz),
			txRed:   make([]byte, 0, MaxSegSz),
		}
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
	asn.Name = ""
	select {
	case asnPool <- asn:
	default:
		asn.del()
	}
	asn = nil
}

// Ack the given requester. If the second argument is *PDU, that is used to
// form the acknowledgment; otherwise, one is pulled from the pool. If the
// following argument is an error, the associate code is used in the negative
// reply with the error string. Otherwise, it's a successful Ack with any
// subsequent args appended as data.
func (asn *ASN) Ack(req Requester, argv ...interface{}) {
	var err error
	if len(argv) == 1 {
		err, _ = argv[0].(error)
	}
	pdu := NewPDU()
	v := asn.version
	v.WriteTo(pdu)
	AckReqId.Version(v).WriteTo(pdu)
	req.WriteTo(pdu)
	if err != nil {
		Trace(asn.Name, "Tx", AckReqId, req, err)
		ErrFromError(err).Version(v).WriteTo(pdu)
		pdu.Write([]byte(err.Error()))
	} else {
		Trace(asn.Name, AckReqId, req, Success)
		Success.Version(v).WriteTo(pdu)
		for _, v := range argv {
			switch t := v.(type) {
			case []byte:
				pdu.Write(t)
			case string:
				pdu.Write([]byte(t))
			case func(io.Writer):
				t(pdu)
			}
		}
	}
	asn.Tx(pdu)
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
	var (
		err error
		pdu *PDU
	)
pduLoop:
	for {
		pdu = NewPDU()
	segLoop:
		for {
			var l uint16
			if _, err = (nbo.Reader{asn}).ReadNBO(&l); err != nil {
				break pduLoop
			}
			n := l & ^MoreFlag
			if n > MaxSegSz {
				err = errors.New("exceeds MaxSegSz")
				break pduLoop
			}
			asn.rxRed = asn.rxRed[:0]
			if _, err = asn.Read(asn.rxRed[:n]); err != nil {
				break pduLoop
			}
			var b []byte
			asn.rxBlack = asn.rxBlack[:0]
			b, err = asn.box.Open(asn.rxBlack[:], asn.rxRed[:n])
			if err != nil {
				break pduLoop
			}
			if _, err = pdu.Write(b); err != nil {
				break pduLoop
			}
			if (l & MoreFlag) == 0 {
				asn.RxQ <- pdu
				pdu = nil
				break segLoop
			}
		}
	}
	pdu.Free()
	asn.RxQ <- nil
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		Println("Error:", asn.Name, "Rx", err)
	} else {
		Println("Quit:", asn.Name)
	}
}

// pdutx pulls PDU from asn.txq, segments, and encrypts before sending
// through asn.conn. This stops on error or nil.
func (asn *ASN) pdutx() {
	const maxBlack = MaxSegSz - box.Overhead
	var (
		err error
		pb  pdubox
	)
pduLoop:
	for {
		if pb = <-asn.txq; pb.pdu == nil {
			break pduLoop
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
			if _, err = (nbo.Writer{asn}).WriteNBO(l); err != nil {
				break segLoop
			}
			if _, err = asn.Write(b); err != nil {
				break segLoop
			}
		}
		pb.pdu.Free()
		pb.pdu = nil
		pb.box = nil
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				Println("Error:", asn.Name, "Tx", err)
			}
			break pduLoop
		}
		if asn.IsQuitting() {
			v := Version(asn.txBlack[0])
			id := Id(asn.txBlack[1])
			if id.Internal(v); id == AckReqId {
				break pduLoop
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

func (asn *ASN) SetBox(box *box.Box) { asn.box = box }

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
func (asn *ASN) Tx(pdu *PDU) { asn.txq <- pdubox{pdu: pdu, box: asn.box} }

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
