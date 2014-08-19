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
	User uint8
	Key  encr.Pub
	Auth auth.Pub

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

func (req *AddReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version,
		pdu.UserAddReqId.Version(version),
		req.User,
		uint8(len(req.Name)),
		uint8(len(req.FBuid)),
		uint8(len(req.FBtoken)),
	})
	h.Write(req.Key[:])
	h.Write(req.Auth[:])
	if len(req.Name) > 0 {
		h.Write([]byte(req.Name))
	}
	if len(req.FBuid) > 0 {
		h.Write([]byte(req.FBuid))
	}
	if len(req.FBtoken) > 0 {
		h.Write([]byte(req.FBtoken))
	}
}

func (req *DelReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.UserDelReqId.Version(version)})
	h.Write(req.Key[:])
}

func (req *SearchReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.UserSearchReqId.Version(version), req.By})
	h.Write([]byte(req.Regex))
}

func (req *VouchReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.UserVouchReqId.Version(version)})
	h.Write(req.Key[:])
	h.Write(req.Sig[:])
	if req.Revoke {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
}

func (req *AddReq) Id() pdu.Id    { return pdu.UserAddReqId }
func (req *DelReq) Id() pdu.Id    { return pdu.UserDelReqId }
func (req *SearchReq) Id() pdu.Id { return pdu.UserSearchReqId }
func (req *VouchReq) Id() pdu.Id  { return pdu.UserVouchReqId }

func (req *AddReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() <= 1+1+1+1+1+1+encr.PubSz+auth.PubSz {
		return pdu.IlFormatErr
	}
	h.Next(2)
	req.User = pdu.Getc(h)
	lName := int(pdu.Getc(h))
	lFBuid := int(pdu.Getc(h))
	lFBtoken := int(pdu.Getc(h))
	if n, err := h.Read(req.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	if n, err := h.Read(req.Auth[:]); err != nil || n != auth.PubSz {
		return pdu.IlFormatErr
	}
	if h.Len() != lName+lFBuid+lFBtoken {
		return pdu.IlFormatErr
	}
	req.Name = pdu.Ngets(h, lName)
	req.FBuid = pdu.Ngets(h, lFBuid)
	req.FBtoken = pdu.Ngets(h, lFBtoken)
	return pdu.Success
}

func (req *DelReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+encr.PubSz {
		return pdu.IlFormatErr
	}
	h.Next(2)
	if n, err := h.Read(req.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	return pdu.Success
}

func (req *SearchReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() <= 1+1+1 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	req.By = pdu.Getc(h)
	req.Regex = pdu.Ngets(h, h.Len())
	return pdu.Success
}

func (req *VouchReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+encr.PubSz+auth.SigSz+1 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	if n, err := h.Read(req.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	if n, err := h.Read(req.Sig[:]); err != nil || n != auth.SigSz {
		return pdu.IlFormatErr
	}
	c := pdu.Getc(h)
	if c != 0 {
		req.Revoke = true
	} else {
		req.Revoke = false
	}
	return pdu.Success
}

func (req *AddReq) String() string {
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

func (req *DelReq) String() string {
	return pdu.UserDelReqId.String() +
		" " + req.Key.String()[:8] + "..."
}

func (req *SearchReq) String() string {
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

func (req *VouchReq) String() string {
	s := ""
	if req.Revoke {
		s = "Revoke "
	}
	return s + req.Key.String()[:8] + "... " + req.Sig.String()[:8] + "..."
}
