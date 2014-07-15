// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"github.com/apptimistco/asn/pdu"
)

type LockReq struct{ Name string }
type ReadReq struct{ Name string }
type RemoveReq struct{ Name string }
type WriteReq struct{ Name string }

func init() {
	pdu.Register(pdu.FileLockReqId, func() pdu.PDUer {
		return &LockReq{}
	})
	pdu.Register(pdu.FileReadReqId, func() pdu.PDUer {
		return &ReadReq{}
	})
	pdu.Register(pdu.FileRemoveReqId, func() pdu.PDUer {
		return &RemoveReq{}
	})
	pdu.Register(pdu.FileWriteReqId, func() pdu.PDUer {
		return &WriteReq{}
	})
}

func NewLockReq(name string) *LockReq     { return &LockReq{Name: name} }
func NewReadReq(name string) *ReadReq     { return &ReadReq{Name: name} }
func NewRemoveReq(name string) *RemoveReq { return &RemoveReq{Name: name} }
func NewWriteReq(name string) *WriteReq   { return &WriteReq{Name: name} }

func (req *LockReq) Format(version uint8) []byte {
	header := []byte{version, pdu.FileLockReqId.Version(version)}
	return append(header, req.Name...)
}

func (req *ReadReq) Format(version uint8) []byte {
	header := []byte{version, pdu.FileReadReqId.Version(version)}
	return append(header, req.Name...)
}

func (req *RemoveReq) Format(version uint8) []byte {
	header := []byte{version, pdu.FileRemoveReqId.Version(version)}
	return append(header, req.Name...)
}

func (req *WriteReq) Format(version uint8) []byte {
	header := []byte{version, pdu.FileWriteReqId.Version(version)}
	return append(header, req.Name...)
}

func (req *LockReq) Parse(header []byte) pdu.Err {
	if len(header) < 1+1+1 {
		return pdu.IlFormatErr
	}
	req.Name = string(header[1+1:])
	return pdu.Success
}

func (req *ReadReq) Parse(header []byte) pdu.Err {
	if len(header) < 1+1+1 {
		return pdu.IlFormatErr
	}
	req.Name = string(header[1+1:])
	return pdu.Success
}

func (req *RemoveReq) Parse(header []byte) pdu.Err {
	if len(header) < 1+1+1 {
		return pdu.IlFormatErr
	}
	req.Name = string(header[1+1:])
	return pdu.Success
}

func (req *WriteReq) Parse(header []byte) pdu.Err {
	if len(header) < 1+1+1 {
		return pdu.IlFormatErr
	}
	req.Name = string(header[1+1:])
	return pdu.Success
}

func (req *LockReq) String(data []byte) string {
	return "\"" + req.Name + "\""
}

func (req *ReadReq) String(data []byte) string {
	return "\"" + req.Name + "\""
}

func (req *RemoveReq) String(data []byte) string {
	return "\"" + req.Name + "\""
}

func (req *WriteReq) String(data []byte) string {
	return "\"" + req.Name + "\""
}
