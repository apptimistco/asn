// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package user

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/encr"
)

const (
	Actual uint8 = iota
	Forum
	Bridge
	NUserTypes
)

const (
	SearchByName uint8 = iota
	SearchByFBuid
	NSearchByTypes
)

type AddReq struct {
	Key  encr.Pub
	Auth auth.Pub
	User uint8

	Name, FBuid, FBtoken string
}

type DelReq struct {
	Key encr.Pub
}

type SearchReq struct {
	By    uint8
	Regex string
}

type VouchReq struct {
	Key    encr.Pub
	Sig    auth.Sig
	Revoke bool
}

func init() {
	pdu.Register(pdu.UserAddReqId, func() pdu.PDUer {
		return &AddReq{}
	})
	pdu.Register(pdu.UserDelReqId, func() pdu.PDUer {
		return &DelReq{}
	})
	pdu.Register(pdu.UserSearchReqId, func() pdu.PDUer {
		return &SearchReq{}
	})
	pdu.Register(pdu.UserVouchReqId, func() pdu.PDUer {
		return &VouchReq{}
	})
}

func NewAddReq(user uint8, name, fbuid, fbtoken string,
	key *encr.Pub, auth *auth.Pub) *AddReq {
	return &AddReq{Name: name,
		FBuid:   fbuid,
		FBtoken: fbtoken,
		Key:     *key,
		Auth:    *auth,
		User:    user,
	}
}

func NewDelReq(key *encr.Pub) *DelReq { return &DelReq{*key} }

func NewSearchReq(by uint8, regex string) *SearchReq {
	return &SearchReq{By: by, Regex: regex}
}

func NewVouchReq(key *encr.Pub, sig *auth.Sig, revoke bool) *VouchReq {
	return &VouchReq{Key: *key, Sig: *sig, Revoke: revoke}
}

func (req *AddReq) Format(version uint8) []byte {
	header := []byte{version, pdu.UserAddReqId.Version(version),
		req.User,
		uint8(len(req.Name)),
		uint8(len(req.FBuid)),
		uint8(len(req.FBtoken)),
	}
	header = append(header, req.Key[:]...)
	header = append(header, req.Auth[:]...)
	if len(req.Name) > 0 {
		header = append(header, []byte(req.Name)...)
	}
	if len(req.FBuid) > 0 {
		header = append(header, []byte(req.FBuid)...)
	}
	if len(req.FBtoken) > 0 {
		header = append(header, []byte(req.FBtoken)...)
	}
	return header
}

func (req *DelReq) Format(version uint8) []byte {
	header := []byte{version, pdu.UserDelReqId.Version(version)}
	return append(header, req.Key[:]...)
}

func (req *SearchReq) Format(version uint8) []byte {
	header := []byte{version, pdu.UserSearchReqId.Version(version)}
	header = append(header, req.By)
	header = append(header, req.Regex...)
	return header
}

func (req *VouchReq) Format(version uint8) []byte {
	header := []byte{version, pdu.UserVouchReqId.Version(version)}
	header = append(header, req.Key[:]...)
	header = append(header, req.Sig[:]...)
	revoke := uint8(0)
	if req.Revoke {
		revoke = 1
	}
	return append(header, revoke)
}

func (add *AddReq) Parse(header []byte) pdu.Err {
	i := 1 + 1 + 1 + 1 + 1 + 1
	if len(header) < i+encr.PubSz+auth.PubSz {
		return pdu.IlFormatErr
	}
	if header[2] >= NUserTypes {
		return pdu.IlFormatErr
	}
	add.User = header[2]
	copy(add.Key[:], header[i:i+encr.PubSz])
	i += encr.PubSz
	copy(add.Auth[:], header[i:i+auth.PubSz])
	i += auth.PubSz
	if l := int(header[3]); l > 0 {
		add.Name = string(header[i : i+l])
		i += l
	}
	if l := int(header[4]); l > 0 {
		add.FBuid = string(header[i : i+l])
		i += l
	}
	if l := int(header[5]); l > 0 {
		add.FBtoken = string(header[i : i+l])
	}
	return pdu.Success
}

func (del *DelReq) Parse(header []byte) pdu.Err {
	if len(header) != 1+1+encr.PubSz {
		return pdu.IlFormatErr
	}
	copy(del.Key[:], header[1+1:])
	return pdu.Success
}

func (req *SearchReq) Parse(header []byte) pdu.Err {
	if len(header) <= 1+1+2 {
		return pdu.IlFormatErr
	}
	req.By = header[1+1]
	req.Regex = string(header[1+1+1:])
	return pdu.Success
}

func (req *VouchReq) Parse(header []byte) pdu.Err {
	if len(header) != 1+1+encr.PubSz+auth.SigSz+1 {
		return pdu.IlFormatErr
	}
	i := 1 + 1
	copy(req.Key[:], header[i:i+encr.PubSz])
	i += encr.PubSz
	copy(req.Sig[:], header[i:i+auth.SigSz])
	if header[i+auth.SigSz] != 0 {
		req.Revoke = true
	} else {
		req.Revoke = false
	}
	return pdu.Success
}

func (req *AddReq) String(_ []byte) string {
	i := req.User
	if i >= NUserTypes {
		i = NUserTypes
	}
	s := [NUserTypes + 1]string{Actual: "Actual",
		Forum:      "Forum",
		Bridge:     "Bridge",
		NUserTypes: "Invalid",
	}[req.User]
	s += " " + req.Key.String()[:8] + "..."
	s += " " + req.Auth.String()[:8] + "..."
	for _, f := range []string{req.Name, req.FBuid, req.FBtoken} {
		if len(f) > 20 {
			s += " \"" + f[:20] + "...\""
		} else {
			s += " \"" + f + "\""
		}
	}
	return s
}

func (req *DelReq) String(_ []byte) string {
	return pdu.UserDelReqId.String() +
		" " + req.Key.String()[:8] + "..."
}

func (req *SearchReq) String(_ []byte) string {
	i := req.By
	if i >= NSearchByTypes {
		i = NSearchByTypes
	}
	s := [NSearchByTypes + 1]string{SearchByName: "Name",
		SearchByFBuid:  "FBuid",
		NSearchByTypes: "invalid",
	}[i]
	return s + " \"" + req.Regex + "\""
}

func (req *VouchReq) String(_ []byte) string {
	s := ""
	if req.Revoke {
		s = "Revoke "
	}
	return s + req.Key.String()[:8] + "... " + req.Sig.String()[:8] + "..."
}
