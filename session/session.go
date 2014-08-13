// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package session

import (
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/auth"
	"github.com/apptimistco/encr"
)

type LoginReq struct {
	Key encr.Pub
	Sig auth.Sig
}
type PauseReq struct{}
type RedirectReq struct{ Url string }
type ResumeReq struct{}
type QuitReq struct{}

func init() {
	pdu.Register(pdu.SessionLoginReqId, func() pdu.PDUer {
		return &LoginReq{}
	})
	pdu.Register(pdu.SessionPauseReqId, func() pdu.PDUer {
		return &PauseReq{}
	})
	pdu.Register(pdu.SessionRedirectReqId, func() pdu.PDUer {
		return &RedirectReq{}
	})
	pdu.Register(pdu.SessionResumeReqId, func() pdu.PDUer {
		return &ResumeReq{}
	})
	pdu.Register(pdu.SessionQuitReqId, func() pdu.PDUer {
		return &QuitReq{}
	})
}

func NewLoginReq(key *encr.Pub, sig *auth.Sig) *LoginReq {
	return &LoginReq{Key: *key, Sig: *sig}
}

func NewPauseReq() *PauseReq { return &PauseReq{} }

func NewRedirectReq(url string) *RedirectReq {
	return &RedirectReq{url}
}

func NewResumeReq() *ResumeReq { return &ResumeReq{} }
func NewQuitReq() *QuitReq     { return &QuitReq{} }

func (req *LoginReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.SessionLoginReqId.Version(version)})
	h.Write(req.Key[:])
	h.Write(req.Sig[:])
}

func (req *PauseReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.SessionPauseReqId.Version(version)})
}

func (req *RedirectReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.SessionRedirectReqId.Version(version)})
	h.Write([]byte(req.Url))
}

func (req *ResumeReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.SessionResumeReqId.Version(version)})
}

func (req *QuitReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.SessionQuitReqId.Version(version)})
}

func (req *LoginReq) Id() pdu.Id    { return pdu.SessionLoginReqId }
func (req *PauseReq) Id() pdu.Id    { return pdu.SessionPauseReqId }
func (req *RedirectReq) Id() pdu.Id { return pdu.SessionRedirectReqId }
func (req *ResumeReq) Id() pdu.Id   { return pdu.SessionResumeReqId }
func (req *QuitReq) Id() pdu.Id     { return pdu.SessionQuitReqId }

func (req *LoginReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+encr.PubSz+auth.SigSz {
		return pdu.IlFormatErr
	}
	h.Next(2)
	if n, err := h.Read(req.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	if n, err := h.Read(req.Sig[:]); err != nil || n != auth.SigSz {
		return pdu.IlFormatErr
	}
	return pdu.Success
}

func (req *PauseReq) Parse(h pdu.Header) pdu.Err { return pdu.Success }

func (req *RedirectReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() <= 1+1 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	req.Url = pdu.Ngets(h, h.Len())
	return pdu.Success
}

func (req *ResumeReq) Parse(_ pdu.Header) pdu.Err { return pdu.Success }
func (req *QuitReq) Parse(_ pdu.Header) pdu.Err   { return pdu.Success }

func (req *LoginReq) String() string {
	return req.Key.String()[:8] + "... " + req.Sig.String()[:8] + "..."
}

func (req *PauseReq) String() string { return "" }

func (req *RedirectReq) String() string {
	if len(req.Url) > 60 {
		return req.Url[:60] + "..."
	}
	return req.Url
}

func (resume *ResumeReq) String() string { return "" }
func (quit *QuitReq) String() string     { return "" }
