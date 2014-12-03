// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn

import (
	"bytes"
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
	// Name of session that's prefaced to trace logs and diagnostics
	Name string
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

// Ack the given requester. If the argument is an error, the associate code is
// used in the negative reply with the error string. Otherwise, it's a
// successful Ack with any subsequent args appended as data.
func (asn *ASN) Ack(req Requester, argv ...interface{}) {
	var (
		err error
		pdu *PDU
	)
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
	if len(argv) == 0 {
		pdu = NewPDUBuf()
	} else {
		f, err := asn.Repos.Tmp.NewFile()
		if err != nil {
			panic("create tmp ack file: " + err.Error())
		}
		pdu = NewPDUFile(f)
		f = nil
	}
	v := asn.version
	v.WriteTo(pdu)
	AckReqId.Version(v).WriteTo(pdu)
	req.WriteTo(pdu)
	if err != nil {
		Trace(asn.Name, "Tx", AckReqId, req, err)
		ErrFromError(err).Version(v).WriteTo(pdu)
		if len(argv) > 0 {
			AckOut(pdu, argv...)
		} else {
			pdu.Write([]byte(err.Error()))
		}
	} else {
		Trace(asn.Name, "Tx", AckReqId, req, Success)
		Success.Version(v).WriteTo(pdu)
		AckOut(pdu, argv...)
	}
	asn.Tx(pdu)
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
					ec  Err
				)
				v.ReadFrom(t)
				id.ReadFrom(t)
				req.ReadFrom(t)
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
func (asn *ASN) NewAckSuccessPDUFile(req Requester) (pdu *PDU, err error) {
	f, err := asn.Repos.Tmp.NewFile()
	if err != nil {
		return
	}
	pdu = NewPDUFile(f)
	f = nil
	v := asn.version
	v.WriteTo(pdu)
	AckReqId.Version(v).WriteTo(pdu)
	req.WriteTo(pdu)
	Success.Version(v).WriteTo(pdu)
	return
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
			Diag.Println(asn.Name, err)
		} else {
			Diag.Println(asn.Name, "Quit")
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
			Diag.Printf("oops pdu %p\n", pdu)
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
			Diag.Println("pdu.Write:", err)
			panic(err)
		}
		if (l & MoreFlag) == 0 {
			Diag.Printf("RXQ pdu %p; len %d\n", pdu, pdu.Len())
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
			Diag.Printf("Extend %p to %s\n", pdu, pdu.FN)
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
pduLoop:
	for {
		if pb = <-asn.txq; pb.pdu == nil {
			break pduLoop
		}
		if err = pb.pdu.Open(); err != nil {
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
			if _, err = (NBOWriter{asn}).WriteNBO(l); err != nil {
				break segLoop
			}
			if _, err = asn.Write(b); err != nil {
				break segLoop
			}
			Diag.Printf("Tx pdu %p; len %d\n", pb.pdu,
				l & ^MoreFlag)
		}
		pb.pdu.Free()
		pb.pdu = nil
		pb.box = nil
		if err != nil {
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
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		Diag.Println(asn.Name, "Error:", err)
	} else {
		Diag.Println(asn.Name, "Quit")
	}
}

// Println formats the given operands with space separation to the log ring
// prefixed by the ASN session Name.
func (asn *ASN) Println(a ...interface{}) (n int, err error) {
	return Println(append([]interface{}{asn.Name}, a...)...)
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
			Diag.Println("Tx", pdu.FN, "size", pdu.Size())
		} else {
			Diag.Println("Tx", pdu.FN)
		}
	} else {
		Diag.Printf("Tx %x\n", pdu.PB.Bytes())
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
