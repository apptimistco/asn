// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import "github.com/apptimistco/asn/pdu"

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

func (req *LockReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.FileLockReqId.Version(version)})
	h.Write([]byte(req.Name))
}

func (req *ReadReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.FileReadReqId.Version(version)})
	h.Write([]byte(req.Name))
}

func (req *RemoveReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.FileRemoveReqId.Version(version)})
	h.Write([]byte(req.Name))
}

func (req *WriteReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.FileWriteReqId.Version(version)})
	h.Write([]byte(req.Name))
}

func (req *LockReq) Id() pdu.Id   { return pdu.FileLockReqId }
func (req *ReadReq) Id() pdu.Id   { return pdu.FileReadReqId }
func (req *RemoveReq) Id() pdu.Id { return pdu.FileRemoveReqId }
func (req *WriteReq) Id() pdu.Id  { return pdu.FileWriteReqId }

func getName(h pdu.Header) (string, pdu.Err) {
	if h.Len() <= 1+1 {
		return "", pdu.IlFormatErr
	}
	h.Next(2)
	return pdu.Ngets(h, h.Len()), pdu.Success
}

func (req *LockReq) Parse(h pdu.Header) (e pdu.Err) {
	req.Name, e = getName(h)
	return
}

func (req *ReadReq) Parse(h pdu.Header) (e pdu.Err) {
	req.Name, e = getName(h)
	return
}

func (req *RemoveReq) Parse(h pdu.Header) (e pdu.Err) {
	req.Name, e = getName(h)
	return
}

func (req *WriteReq) Parse(h pdu.Header) (e pdu.Err) {
	req.Name, e = getName(h)
	return
}

func (req *LockReq) String() string {
	return "\"" + req.Name + "\""
}

func (req *ReadReq) String() string {
	return "\"" + req.Name + "\""
}

func (req *RemoveReq) String() string {
	return "\"" + req.Name + "\""
}

func (req *WriteReq) String() string {
	return "\"" + req.Name + "\""
}
