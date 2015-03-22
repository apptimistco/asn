// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/apptimistco/asn/debug"
	"github.com/apptimistco/asn/debug/file"
	"github.com/apptimistco/asn/debug/mutex"
)

const PDUBufSz = 4096

var (
	pdus struct {
		mutex.Mutex
		pool   chan *PDU
		bufs   chan *PB
		debug  func(int, *PDU, string)
		newPDU func() *PDU
	}

	PduDiag *debug.Logger

	ErrPDUInvalid = errors.New("invalid PDU (neither File nor Buffer)")
	ErrPDUOverrun = errors.New("overrun PDU Buffer")
)

func init() {
	pdus.pool = make(chan *PDU, 16)
	pdus.bufs = make(chan *PB, 16)
	pdus.Mutex.Set("pdu")
}

func FlushPDU() {
	for {
		select {
		case <-pdus.bufs:
		case <-pdus.pool:
		default:
			return
		}
	}
}

type PDU struct {
	File  *file.File
	FN    string
	PB    *PB
	Limit int64
	ref   int
}

func NewPDU() (pdu *PDU) {
	select {
	case t := <-pdus.pool:
		pdu = t
		pdu.Diag(debug.Depth(3), "recycled")
	default:
		pdu = new(PDU)
		pdu.Diag(debug.Depth(3), "new")
	}
	pdu.ref = 1
	return
}

func NewPDUBuf() (pdu *PDU) {
	pdu = NewPDU()
	select {
	case t := <-pdus.bufs:
		pdu.PB = t
		pdu.Diag(debug.Depth(2), pdu.PB.DiagString("recycled"))
	default:
		pdu.PB = new(PB)
		pdu.Diag(debug.Depth(2), pdu.PB.DiagString("new"))
	}
	return
}

func NewPDUFile(file *file.File) (pdu *PDU) {
	pdu = NewPDU()
	pdu.File = file
	pdu.FN = file.Name()
	pdu.Diag(debug.Depth(2), "file", pdu.FN, "recast")
	return
}

func NewPDUFN(fn string) (pdu *PDU) {
	pdu = NewPDU()
	pdu.FN = fn
	pdu.Diag(debug.Depth(2), "file", pdu.FN, "new")
	return
}

func (pdu *PDU) Close() (err error) {
	if pdu.File != nil {
		err = pdu.File.Close()
		pdu.File = nil
	}
	return
}

func (pdu *PDU) Clone() {
	pdus.Lock()
	defer pdus.Unlock()
	pdu.ref += 1
}

// copier reads data from R and writes it to W until limit, EOF or error. The
// return value n is the number of bytes read. Any error except io.EOF
// encountered during the read is also returned.
func (pdu *PDU) copier(r io.Reader, w io.Writer) (n int64, err error) {
	for err == nil && (pdu.Limit == 0 || n < pdu.Limit) {
		var buf [PDUBufSz]byte
		end := PDUBufSz
		if delta := pdu.Limit - n; delta > 0 && int(delta) < PDUBufSz {
			end = int(delta)
		}
		nr, rerr := r.Read(buf[:end])
		if nr >= 0 {
			nw, werr := w.Write(buf[:nr])
			if nw >= 0 {
				n += int64(nw)
			}
			if werr != nil {
				err = werr
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				err = rerr
			}
			break
		}
	}
	return
}

func (pdu *PDU) deref() int {
	pdus.Lock()
	defer pdus.Unlock()
	pdu.ref -= 1
	return pdu.ref
}

// If built with "diag" and "pdu" tags, Diag sends Sprintln(v...) output
// to the Diag logger.
func (pdu *PDU) Diag(v ...interface{}) {
	if PduDiag == nil {
		return
	}
	depth, v := debug.FilterDepth(v...)
	PduDiag.Output(depth, fmt.Sprintf("pdu %p %s", pdu, fmt.Sprintln(v...)))
}

// Error returns the unread portion of the pdu as an error.
func (pdu *PDU) Error() error {
	if pdu.Len() > 0 {
		b := make([]byte, pdu.Len())
		pdu.Read(b)
		return &PDUError{b}
	}
	return &PDUError{[]byte("unknown")}
}

func (pdu *PDU) Free() {
	if pdu == nil {
		pdus.Diag(debug.Depth(2), "nil")
		return
	}
	if pdu.deref() > 0 {
		return
	}
	if pdu.File != nil {
		pdu.File.Close()
		pdu.File = nil
	}
	if pdu.FN != "" {
		if IsTmp(pdu.FN) || IsBridge(pdu.FN) {
			os.Remove(pdu.FN)
			pdu.Diag(debug.Depth(2), "file", pdu.FN, "removed")
		}
		pdu.FN = ""
	}
	if pdu.PB != nil {
		pdu.Diag(debug.Depth(2), pdu.PB.DiagString("free"))
		pdu.PB.Free()
		pdu.PB = nil
	}
	pdu.Diag(debug.Depth(2), "free")
	select {
	case pdus.pool <- pdu:
	}
}

func (pdu *PDU) Len() int {
	if pdu.File != nil {
		pos, err := pdu.File.Seek(0, os.SEEK_CUR)
		if err != nil {
			return -1
		}
		return int(pdu.Size() - pos)
	} else if pdu.PB != nil {
		return pdu.PB.wo - pdu.PB.ro
	}
	return -1
}

func (pdu *PDU) Open() (err error) {
	if pdu.PB != nil {
		pdu.PB.ro = 0
	} else if pdu.File != nil {
		_, err = pdu.File.Seek(0, os.SEEK_SET)
	} else {
		pdu.File, err = file.Open(pdu.FN)
	}
	return
}

// Read reads the next len(b) bytes from pdu or until the it's drained. The
// return value n is the number of bytes read. If pdu has nothing to return,
// err is io.EOF (unless len(b) is zero); otherwise it is nil.
func (pdu *PDU) Read(b []byte) (int, error) {
	if pdu.File != nil {
		return pdu.File.Read(b)
	} else if pdu.PB != nil {
		return pdu.PB.Read(b)
	}
	pdus.Diag(pdu.FN, ErrPDUInvalid)
	return 0, ErrPDUInvalid
}

// ReadFrom reads from r until limit, EOF, error, or buffer length. The return
// value n is the number of bytes read. Any error except io.EOF encountered
// during the read is also returned.
func (pdu *PDU) ReadFrom(r io.Reader) (int64, error) {
	if pdu.File != nil {
		return pdu.copier(r, pdu.File)
	} else if pdu.PB != nil {
		end := PDUBufSz
		if pdu.Limit != 0 {
			end = int(pdu.Limit)
		}
		i, err := r.Read(pdu.PB.buf[:end])
		if err == io.EOF {
			err = nil
		}
		return int64(i), err
	}
	pdus.Diag(pdu.FN, ErrPDUInvalid)
	return 0, ErrPDUInvalid
}

// Rseek moves file or buf read offset.
func (pdu *PDU) Rseek(n int64, whence int) (ret int64, err error) {
	if pdu.File != nil {
		ret, err = pdu.File.Seek(n, whence)
	} else if pdu.PB != nil {
		switch whence {
		case os.SEEK_SET:
			if n >= PDUBufSz {
				err = ErrPDUOverrun
			} else {
				pdu.PB.ro = int(n)
			}
			ret = int64(pdu.PB.ro)
		case os.SEEK_CUR:
			if i := pdu.PB.ro + int(n); i >= PDUBufSz {
				err = ErrPDUOverrun
			} else {
				pdu.PB.ro = i
			}
			ret = int64(pdu.PB.ro)
		case os.SEEK_END:
			if i := pdu.PB.wo + int(n); i >= PDUBufSz {
				err = ErrPDUOverrun
			} else {
				pdu.PB.ro = i
			}
			ret = int64(pdu.PB.ro)
		default:
			err = os.ErrInvalid
		}
	} else {
		err = ErrPDUInvalid
	}
	return
}

// Size returns number of bytes written to PDU.
func (pdu *PDU) Size() int64 {
	if pdu.File != nil {
		fi, err := pdu.File.Stat()
		if err != nil {
			return -1
		}
		return fi.Size()
	} else if pdu.PB != nil {
		return int64(pdu.PB.wo)
	}
	return -1
}

func (pdu *PDU) Write(b []byte) (int, error) {
	if pdu.File != nil {
		return pdu.File.Write(b)
	} else if pdu.PB != nil {
		return pdu.PB.Write(b)
	}
	pdus.Diag(ErrPDUInvalid)
	return 0, ErrPDUInvalid
}

func (pdu *PDU) WriteTo(w io.Writer) (int64, error) {
	if pdu.File != nil {
		return pdu.copier(pdu.File, w)
	} else if pdu.PB != nil {
		end := pdu.PB.wo
		if l := int(pdu.Limit); l != 0 && l < pdu.PB.wo-pdu.PB.ro {
			end = pdu.PB.ro + l
		}
		i, err := w.Write(pdu.PB.buf[pdu.PB.ro:end])
		if err == io.EOF {
			err = nil
		}
		pdu.PB.ro += i
		return int64(i), err
	}
	pdus.Diag(pdu.FN, ErrPDUInvalid)
	return 0, ErrPDUInvalid
}

type PB struct {
	buf    [PDUBufSz]byte
	ro, wo int
}

func (pb *PB) Bytes() []byte {
	return pb.buf[pb.ro:pb.wo]
}

// If built with "diag" and "pdu" tags, DiagString returns Sprint(v...)
// output prefaced by "buf %p"
// to the Diag logger.
func (pb *PB) DiagString(v ...interface{}) string {
	if PduDiag == nil {
		return ""
	}
	return fmt.Sprintf("buf %p %s", pb, fmt.Sprint(v...))
}

func (pb *PB) Free() {
	if pb == nil {
		return
	}
	pb.ro = 0
	pb.wo = 0
	select {
	case pdus.bufs <- pb:
	}
}

func (pb *PB) Read(b []byte) (int, error) {
	if pb.ro >= pb.wo {
		if len(b) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	end := pb.ro + len(b)
	if end > pb.wo {
		end = pb.wo
	}
	n := copy(b, pb.buf[pb.ro:end])
	pb.ro += n
	return n, nil
}

func (pb *PB) Write(b []byte) (int, error) {
	end := pb.wo + len(b)
	if end >= PDUBufSz {
		return 0, ErrPDUOverrun
	}
	n := copy(pb.buf[pb.wo:end], b)
	if n != len(b) {
		return n, io.EOF
	} else {
		pb.wo += n
	}
	return n, nil
}

type PDUError struct {
	buf []byte
}

func (err *PDUError) Error() string { return string(err.buf) }
