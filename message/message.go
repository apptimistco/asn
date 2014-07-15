// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package message

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/encr"
	"time"
)

type Id [sha512.Size]byte

type HeadRpt struct {
	Key  encr.Pub
	Head Id
}

type MessageReq struct {
	Time uint64
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

func NewMessageReq(time uint64, to, from *encr.Pub) *MessageReq {
	return &MessageReq{Time: time, To: *to, From: *from}
}

func (rpt *HeadRpt) Format(version uint8) []byte {
	header := []byte{version, pdu.HeadRptId.Version(version)}
	header = append(header, rpt.Key[:]...)
	return append(header, rpt.Head[:]...)
}

func (req *MessageReq) Format(version uint8) []byte {
	header := []byte{version, pdu.MessageReqId.Version(version)}
	time := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(time, req.Time)
	header = append(header, time...)
	header = append(header, req.To[:]...)
	return append(header, req.From[:]...)
}

func (rpt *HeadRpt) Parse(header []byte) pdu.Err {
	i := 1 + 1
	if len(header) != i+encr.PubSz+sha512.Size {
		return pdu.IlFormatErr
	}
	copy(rpt.Key[:], header[i:i+encr.PubSz])
	i += encr.PubSz
	copy(rpt.Head[:], header[i:])
	return pdu.Success
}

func (req *MessageReq) Parse(header []byte) pdu.Err {
	i := 1 + 1
	if len(header) != i+8+encr.PubSz+encr.PubSz {
		return pdu.IlFormatErr
	}
	req.Time = binary.BigEndian.Uint64(header[i : i+8])
	i += 8
	copy(req.To[:], header[i:i+encr.PubSz])
	i += encr.PubSz
	copy(req.From[:], header[i:i+encr.PubSz])
	return pdu.Success
}

func (rpt *HeadRpt) String(_ []byte) string {
	return rpt.Key.String()[:8] + "... " + rpt.Head.String()[:8] + "..."
}

func (req *MessageReq) String(data []byte) string {
	s := time.Unix(int64(req.Time), 0).Format(time.RFC822Z)
	s += " " + req.To.String()[:8] + "..."
	s += " " + req.From.String()[:8] + "..."
	if len(data) > 8 {
		s += " " + hex.EncodeToString(data[:8]) + "..."
	} else {
		s += " " + hex.EncodeToString(data)
	}
	return s
}

func (id Id) String() string { return hex.EncodeToString(id[:]) }
