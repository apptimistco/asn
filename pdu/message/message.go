// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package message

import (
	"crypto/sha512"
	"encoding/hex"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/asn/time"
	"github.com/apptimistco/encr"
	"github.com/apptimistco/nbo"
)

type Id [sha512.Size]byte

type HeadRpt struct {
	Key  encr.Pub
	Head Id
}

type MessageReq struct {
	Time time.Time
	To   encr.Pub
	From encr.Pub
}

func init() {
	pdu.Register(pdu.HeadRptId, func() pdu.PDUer {
		return &HeadRpt{}
	})
	pdu.Register(pdu.MessageReqId, func() pdu.PDUer {
		return &MessageReq{}
	})
}

func NewId(msg []byte) Id { return Id(sha512.Sum512(msg)) }

func NewHeadRpt(key *encr.Pub, head *Id) *HeadRpt {
	return &HeadRpt{Key: *key, Head: *head}
}

func NewMessageReq(to, from *encr.Pub) *MessageReq {
	return &MessageReq{Time: time.Now(), To: *to, From: *from}
}

func (rpt *HeadRpt) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.HeadRptId.Version(version)})
	h.Write(rpt.Key[:])
	h.Write(rpt.Head[:])
}

func (req *MessageReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.MessageReqId.Version(version)})
	(nbo.Writer{h}).WriteNBO(uint64(req.Time.Unix()))
	h.Write(req.To[:])
	h.Write(req.From[:])
}

func (req *HeadRpt) Id() pdu.Id    { return pdu.HeadRptId }
func (req *MessageReq) Id() pdu.Id { return pdu.MessageReqId }

func (rpt *HeadRpt) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+encr.PubSz+sha512.Size {
		return pdu.IlFormatErr
	}
	h.Next(2)
	if n, err := h.Read(rpt.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	if n, err := h.Read(rpt.Head[:]); err != nil || n != sha512.Size {
		return pdu.IlFormatErr
	}
	return pdu.Success
}

func (req *MessageReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+8+(2*encr.PubSz) {
		return pdu.IlFormatErr
	}
	h.Next(2)
	var u64 uint64
	(nbo.Reader{h}).ReadNBO(&u64)
	req.Time = time.Unix(int64(u64), 0)
	if n, err := h.Read(req.To[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	if n, err := h.Read(req.From[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	return pdu.Success
}

func (rpt *HeadRpt) String() string {
	return rpt.Key.String()[:8] + "... " + rpt.Head.String()[:8] + "..."
}

func (req *MessageReq) String() string {
	s := req.Time.String()
	s += " " + req.To.String()[:8] + "..."
	s += " " + req.From.String()[:8] + "..."
	return s
}

func (id Id) String() string { return hex.EncodeToString(id[:]) }
