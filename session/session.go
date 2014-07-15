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

func (req *LoginReq) Format(version uint8) []byte {
	header := []byte{version, pdu.SessionLoginReqId.Version(version)}
	header = append(header, req.Key[:]...)
	header = append(header, req.Sig[:]...)
	return header
}

func (req *PauseReq) Format(version uint8) []byte {
	return []byte{version, pdu.SessionPauseReqId.Version(version)}
}

func (req *RedirectReq) Format(version uint8) []byte {
	header := []byte{version, pdu.SessionRedirectReqId.Version(version)}
	return append(header, []byte(req.Url)...)
}

func (req *ResumeReq) Format(version uint8) []byte {
	return []byte{version, pdu.SessionResumeReqId.Version(version)}
}

func (req *QuitReq) Format(version uint8) []byte {
	return []byte{version, pdu.SessionQuitReqId.Version(version)}
}

func (req *LoginReq) Parse(header []byte) pdu.Err {
	i := 1 + 1
	if len(header) != i+encr.PubSz+auth.SigSz {
		return pdu.IlFormatErr
	}
	l := encr.PubSz
	copy(req.Key[:], header[i:i+l])
	i += l
	copy(req.Sig[:], header[i:])
	return pdu.Success
}

func (req *PauseReq) Parse(_ []byte) pdu.Err { return pdu.Success }

func (req *RedirectReq) Parse(header []byte) pdu.Err {
	if len(header) <= 1+1 {
		return pdu.IlFormatErr
	}
	req.Url = string(header[1+1:])
	return pdu.Success
}

func (req *ResumeReq) Parse(_ []byte) pdu.Err { return pdu.Success }
func (req *QuitReq) Parse(_ []byte) pdu.Err   { return pdu.Success }

func (req *LoginReq) String(_ []byte) string {
	return req.Key.String()[:8] + "... " + req.Sig.String()[:8] + "..."
}

func (req *PauseReq) String(_ []byte) string { return "" }

func (req *RedirectReq) String(_ []byte) string {
	if len(req.Url) > 60 {
		return req.Url[:60] + "..."
	}
	return req.Url
}

func (resume *ResumeReq) String(_ []byte) string { return "" }
func (quit *QuitReq) String(_ []byte) string     { return "" }
