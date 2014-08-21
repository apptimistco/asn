// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package repos

import (
	"crypto/sha512"
	"encoding/hex"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/encr"
	"github.com/apptimistco/nbo"
	"io"
	"os"
	"strconv"
)

func init() {
	pdu.Register(pdu.ObjGetReqId, func() pdu.PDUer {
		req := &ObjGetReq{}
		req.List = make([]ObjId, 0)
		return req
	})
	pdu.Register(pdu.ObjPutReqId, func() pdu.PDUer {
		req := &ObjPutReq{}
		req.List = make([]ObjRec, 0)
		return req
	})
	pdu.Register(pdu.RefGetReqId, func() pdu.PDUer { return &RefGetReq{} })
	pdu.Register(pdu.RefPutReqId, func() pdu.PDUer {
		req := &RefPutReq{}
		req.List = make([]ObjId, 0)
		return req
	})
}

// ObjGetReq PDU requests download of one or more ASN objects.
//
//	ObjGetReq = Version Id ObjId...
//	Version = uint8{ 0 }
//	Id = uint8{ ObjGetReqId }
//	ObjId = [64]uint8
//
// The positive acknowledgment data for ObjGetReq must have one or more of
// these ObjDataRec.
//
//	AckData = ObjDataRec...
//	ObjDataRec = ObjId + ObjDataLen + ObjData
//	ObjId = [64]uint8
//	ObjDataLen = uint32
//	ObjData = [ObjDataLen]uint8
//
// The data of any negative acknowledgment must list each failed ObjId.
type ObjGetReq struct {
	List []ObjId
}

func NewObjGetReq(ids ...ObjId) *ObjGetReq {
	req := &ObjGetReq{make([]ObjId, len(ids))}
	req.Append(ids...)
	return req
}

func (req *ObjGetReq) Append(ids ...ObjId) {
	req.List = append(req.List, ids...)
}

func (req *ObjGetReq) Close() error {
	req.List = req.List[:0]
	req.List = nil
	return nil
}

func (req *ObjGetReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.ObjGetReqId.Version(version)})
	for _, id := range req.List {
		h.Write(id[:])
	}
}

func (req *ObjGetReq) Id() pdu.Id { return pdu.ObjGetReqId }

func (req *ObjGetReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() < 1+1+sha512.Size {
		return pdu.IlFormatErr
	}
	h.Next(2)
	for {
		id := new(ObjId)
		n, err := h.Read(id[:])
		if err == io.EOF {
			id = nil
			break
		} else if err != nil || n != sha512.Size {
			id = nil
			return pdu.IlFormatErr
		}
		req.Append(*id)
	}
	return pdu.Success
}

func (req *ObjGetReq) String() (s string) {
	for i, id := range req.List {
		if i > 0 {
			s += " "
		}
		if i == 8 {
			s += "..."
			break
		}
		s += id.String()[:8] + "..."
	}
	return
}

// ASN objects are identified by the 64-byte SHA-512 sum of the content.
type ObjId [sha512.Size]uint8

func (id ObjId) String() string { return hex.EncodeToString(id[:]) }

// NewObjId sums the given file.
func NewObjId(name string) (o ObjId) {
	f, err := os.Open(name)
	if err != nil {
		return
	}
	defer f.Close()
	h := sha512.New()
	io.Copy(h, f)
	copy(o[:], h.Sum([]byte{}))
	return
}

// ObjPutReq PDU requests upload of one or more ASN objects.
//
//	ObjPutReq = Version Id ObjRec...
//	Version = uint8{ 0 }
//	Id = uint8{ ObjPutReqId }
//	ObjRec = ObjId + ObjDatalen
//	ObjId = [64]uint8
//	ObjDataLen = uint32
//
// The ObjPutReq PDU data contains the concatenated object data.
//
// The data of the negative acknowledgment must list each failed ObjId.
// Likewise, positive acknowledgment data must list each successful ObjId.
type ObjPutReq struct {
	List []ObjRec
}

func NewObjPutReq(recs ...ObjRec) *ObjPutReq {
	req := &ObjPutReq{make([]ObjRec, len(recs))}
	req.Append(recs...)
	return req
}

func (req *ObjPutReq) Append(recs ...ObjRec) {
	req.List = append(req.List, recs...)
}

func (req *ObjPutReq) Close() error {
	req.List = req.List[:0]
	req.List = nil
	return nil
}

func (req *ObjPutReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.ObjPutReqId.Version(version)})
	for _, rec := range req.List {
		h.Write(rec.Id[:])
		(nbo.Writer{h}).WriteNBO(rec.Len)
	}
}

func (req *ObjPutReq) Id() pdu.Id { return pdu.ObjPutReqId }

func (req *ObjPutReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() < 1+1+sha512.Size+4 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	for {
		rec := new(ObjRec)
		n, err := h.Read(rec.Id[:])
		if err == io.EOF {
			rec = nil
			break
		} else if err != nil || n != sha512.Size {
			rec = nil
			return pdu.IlFormatErr
		}
		n, err = (nbo.Reader{h}).ReadNBO(&rec.Len)
		if err != nil || n != 4 {
			return pdu.IlFormatErr
		}
		req.Append(*rec)
	}
	return pdu.Success
}

func (req *ObjPutReq) String() (s string) {
	for i, rec := range req.List {
		if i > 0 {
			s += " "
		}
		if i == 6 {
			s += "..."
			break
		}
		s += rec.Id.String()[:8] + "... "
		s += strconv.Itoa(int(rec.Len))
	}
	return
}

// Each ObjRec includes the ASN object identifier (SHA) and its length.
type ObjRec struct {
	Id  ObjId
	Len uint32
}

// RefGetReq PDU requests the object references of a given user.
//
//	RefGetReq = Version Id Key Off N
//	Version = uint8{ 0 }
//	Id = uint8{ RefGetReqId }
//	Key = [32]uint8
//	Off = uint32	( 0: tree; 0xffffffff: last message )
//	N = uint32	( 0: to EOF )
//
// The positive acknowledgment data for RefGetReq must begin with the key for
// reference followed by an object identifier list, if any. The negative
// acknowledgment data will just have the key.
type RefGetReq struct {
	Key encr.Pub
	Off uint32
	N   uint32
}

func NewRefGetReq(key *encr.Pub, off, n uint32) *RefGetReq {
	return &RefGetReq{*key, off, n}
}

func (req *RefPutReq) Append(ids ...ObjId) {
	req.List = append(req.List, ids...)
}

func (req *RefPutReq) Close() error {
	req.List = req.List[:0]
	req.List = nil
	return nil
}

func (req *RefGetReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.RefGetReqId.Version(version)})
	h.Write(req.Key[:])
	(nbo.Writer{h}).WriteNBO(req.Off)
	(nbo.Writer{h}).WriteNBO(req.N)
}

func (req *RefGetReq) Id() pdu.Id { return pdu.RefGetReqId }

func (req *RefPutReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() < 1+1+encr.PubSz+sha512.Size {
		return pdu.IlFormatErr
	}
	h.Next(2)
	if n, err := h.Read(req.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	for {
		id := new(ObjId)
		n, err := h.Read(id[:])
		if err == io.EOF {
			id = nil
			break
		} else if err != nil || n != sha512.Size {
			id = nil
			return pdu.IlFormatErr
		}
		req.Append(*id)
	}
	return pdu.Success
}

func (req *RefGetReq) String() (s string) {
	s = req.Key.String()[:8] + "... "
	s += strconv.Itoa(int(req.Off)) + " "
	s += strconv.Itoa(int(req.N))
	return
}

// RefPutReq PDU requests modifying the user tree reference or appending to
// their message reference list.
//
//	RefPutReq = Version Id Key ObjId...
//	Version = uint8{ 0 }
//	Id = uint8{ ObjGetReqId }
//	Key = [32]uint8
//	ObjId = [64]uint8
//
// If the referenced object is a tree, the given user's tree reference is
// updated providing that the requested user has permission and that the tree
// is newer than the current entry.
//
// Both positive or negative acknowledgment data for RefPutReq must have the
// requested key.
type RefPutReq struct {
	Key  encr.Pub
	List []ObjId
}

func NewRefPutReq(key *encr.Pub, ids ...ObjId) *RefPutReq {
	req := &RefPutReq{Key: *key, List: make([]ObjId, len(ids))}
	req.Append(ids...)
	return req
}

func (req *RefGetReq) Close() error { return nil }

func (req *RefPutReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.RefPutReqId.Version(version)})
	h.Write(req.Key[:])
	for _, id := range req.List {
		h.Write(id[:])
	}
}

func (req *RefPutReq) Id() pdu.Id { return pdu.RefPutReqId }

func (req *RefGetReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+encr.PubSz+4+4 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	if n, err := h.Read(req.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	(nbo.Reader{h}).ReadNBO(&req.Off)
	(nbo.Reader{h}).ReadNBO(&req.N)
	return pdu.Success
}

func (req *RefPutReq) String() (s string) {
	s = req.Key.String()[:8]
	s += "... "
	for i, id := range req.List {
		if i > 0 {
			s += " "
		}
		if i == 7 {
			s += "..."
			break
		}
		s += id.String()[:8] + "..."
	}
	return
}
