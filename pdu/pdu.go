// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdu

import "errors"

const (
	RawId Id = iota
	AckId
	EchoId
	FileLockReqId
	FileReadReqId
	FileRemoveReqId
	FileWriteReqId
	HeadRptId
	MarkReqId
	MarkRptId
	MessageReqId
	SessionLoginReqId
	SessionPauseReqId
	SessionQuitReqId
	SessionRedirectReqId
	SessionResumeReqId
	TraceReqId
	UserAddReqId
	UserDelReqId
	UserSearchReqId
	UserVouchReqId
	NpduIds

	DeniedId
	FailureId
	IlFormatId
	IncompatibleId
	RedirectId
	ShortId
	UnexpectedId
	UnknownId
	UnsupportedId

	Ncounters

	TraceRxId
	TraceTxId
	Nids

	SuccessId = NpduIds
	Nerrors   = uint(Ncounters - NpduIds)

	Success         = Err(SuccessId - NpduIds)
	DeniedErr       = Err(DeniedId - NpduIds)
	FailureErr      = Err(FailureId - NpduIds)
	IlFormatErr     = Err(IlFormatId - NpduIds)
	IncompatibleErr = Err(IncompatibleId - NpduIds)
	RedirectErr     = Err(RedirectId - NpduIds)
	ShortErr        = Err(ShortId - NpduIds)
	UnexpectedErr   = Err(UnexpectedId - NpduIds)
	UnknownErr      = Err(UnknownId - NpduIds)
	UnsupportedErr  = Err(UnsupportedId - NpduIds)

	Version = 0
	MaxId   = 32
	MaxErr  = 16
)

const (
	_ byte = iota
	ackV0
	echoV0
	fileLockReqV0
	fileReadReqV0
	fileRemoveReqV0
	fileWriteReqV0
	headRptV0
	markReqV0
	markRptV0
	locationStreamReqV0
	messageReqV0
	sessionLoginReqV0
	sessionPauseReqV0
	sessionQuitReqV0
	sessionRedirectReqV0
	sessionResumeReqV0
	traceReqV0
	userAddReqV0
	userDelReqV0
	userSearchReqV0
	userVouchReqV0
)

const (
	successV0 byte = iota
	deniedV0
	failureV0
	ilFormatV0
	incompatibleV0
	redirectV0
	shortV0
	unexpectedV0
	unknownV0
	unsupportedV0
)

var (
	// These aren't Nack'd
	ErrDisestablished = errors.New("Disestablished session")
	ErrSuspended      = errors.New("Suspended session")
	ErrParse          = errors.New("Internal parse error")
	ErrQuery          = errors.New("invalid or missing query string")

	// These are Nack'd
	ErrDenied       = errors.New("Permission denied")
	ErrFailure      = errors.New("Unspecified request PDU Failure")
	ErrIlFormat     = errors.New("Il formatted PDU")
	ErrIncompatible = errors.New("Incompatible version")
	ErrRedirect     = errors.New("Resource redirection (non-error)")
	ErrShort        = errors.New("Short PDU header")
	ErrUnexpected   = errors.New("Unexpected PDU")
	ErrUnknown      = errors.New("Unknown PDU")
	ErrUnsupported  = errors.New("Unsupported PDU")

	Errors = [Nerrors]error{
		DeniedErr:       ErrDenied,
		FailureErr:      ErrFailure,
		IlFormatErr:     ErrIlFormat,
		IncompatibleErr: ErrIncompatible,
		RedirectErr:     ErrRedirect,
		ShortErr:        ErrShort,
		UnexpectedErr:   ErrUnexpected,
		UnknownErr:      ErrUnknown,
		UnsupportedErr:  ErrUnsupported,
	}
)

type Err uint8

// NormErr converts the received (version, Err) to an internal Err.
func NormErr(rxVersion, rxErr byte) Err {
	if rxVersion > Version {
		return IncompatibleErr
	}
	i := uint((rxVersion * MaxErr) | rxErr)
	if i > Nerrors {
		return UnknownErr
	}
	return [(Version + 1) * MaxErr]Err{
		((0 * MaxErr) | successV0):      Success,
		((0 * MaxErr) | deniedV0):       DeniedErr,
		((0 * MaxErr) | failureV0):      FailureErr,
		((0 * MaxErr) | ilFormatV0):     IlFormatErr,
		((0 * MaxErr) | incompatibleV0): IncompatibleErr,
		((0 * MaxErr) | redirectV0):     RedirectErr,
		((0 * MaxErr) | shortV0):        ShortErr,
		((0 * MaxErr) | unexpectedV0):   UnexpectedErr,
		((0 * MaxErr) | unknownV0):      UnknownErr,
		((0 * MaxErr) | unsupportedV0):  UnsupportedErr,
	}[i]
}

// String returns the name of internal Err.
func (err Err) String() string {
	if err == Success {
		return "Success"
	}
	i := int(err)
	if uint(err) >= Nerrors {
		i = int(UnknownErr)
	}
	return [Nerrors]error{
		DeniedErr:       ErrDenied,
		FailureErr:      ErrFailure,
		IlFormatErr:     ErrIlFormat,
		IncompatibleErr: ErrIncompatible,
		RedirectErr:     ErrRedirect,
		ShortErr:        ErrShort,
		UnexpectedErr:   ErrUnexpected,
		UnknownErr:      ErrUnknown,
		UnsupportedErr:  ErrUnsupported,
	}[i].Error()
}

// Version returns the given version of an Err in byte form.
func (err Err) Version(version uint8) byte {
	if version > Version {
		version = Version
	}
	i := int((version * MaxErr) | uint8(err))
	return [(Version + 1) * MaxErr]byte{
		((0 * MaxErr) | Success):         successV0,
		((0 * MaxErr) | DeniedErr):       deniedV0,
		((0 * MaxErr) | FailureErr):      failureV0,
		((0 * MaxErr) | IlFormatErr):     ilFormatV0,
		((0 * MaxErr) | IncompatibleErr): incompatibleV0,
		((0 * MaxErr) | RedirectErr):     redirectV0,
		((0 * MaxErr) | ShortErr):        shortV0,
		((0 * MaxErr) | UnexpectedErr):   unexpectedV0,
		((0 * MaxErr) | UnknownErr):      unknownV0,
		((0 * MaxErr) | UnsupportedErr):  unsupportedV0,
	}[i]
}

type Id uint8

// IsErr tests whether an Id is an error.
func (id Id) IsErr() bool { return id > NpduIds && id < Ncounters }

// Err converts an Id to an Err.
func (id Id) Err() Err { return Err(id - NpduIds) }

// NormId converts the received (version, Id) to an internal Id.
func NormId(rxVersion, rxId byte) Id {
	if rxVersion > Version {
		return IncompatibleId
	}
	i := uint((rxVersion * MaxId) | rxId)
	if i > uint(NpduIds) {
		return UnknownId
	}
	id := [(Version + 1) * MaxId]Id{
		((0 * MaxId) | ackV0):                AckId,
		((0 * MaxId) | echoV0):               EchoId,
		((0 * MaxId) | fileLockReqV0):        FileLockReqId,
		((0 * MaxId) | fileReadReqV0):        FileReadReqId,
		((0 * MaxId) | fileRemoveReqV0):      FileRemoveReqId,
		((0 * MaxId) | fileWriteReqV0):       FileWriteReqId,
		((0 * MaxId) | headRptV0):            HeadRptId,
		((0 * MaxId) | markReqV0):            MarkReqId,
		((0 * MaxId) | markRptV0):            MarkRptId,
		((0 * MaxId) | messageReqV0):         MessageReqId,
		((0 * MaxId) | sessionLoginReqV0):    SessionLoginReqId,
		((0 * MaxId) | sessionPauseReqV0):    SessionPauseReqId,
		((0 * MaxId) | sessionQuitReqV0):     SessionQuitReqId,
		((0 * MaxId) | sessionRedirectReqV0): SessionRedirectReqId,
		((0 * MaxId) | sessionResumeReqV0):   SessionResumeReqId,
		((0 * MaxId) | traceReqV0):           TraceReqId,
		((0 * MaxId) | userAddReqV0):         UserAddReqId,
		((0 * MaxId) | userDelReqV0):         UserDelReqId,
		((0 * MaxId) | userSearchReqV0):      UserSearchReqId,
		((0 * MaxId) | userVouchReqV0):       UserVouchReqId,
	}[i]
	if uint8(id) == 0 {
		return UnknownId
	}
	return id
}

// String returns the name of internal Id.
func (id Id) String() string {
	i := int(id)
	if id >= Nids {
		i = int(UnknownId)
	}
	return [Nids]string{
		AckId:                "Ack",
		EchoId:               "Echo",
		FileLockReqId:        "FileLockReq",
		FileReadReqId:        "FileReadReq",
		FileRemoveReqId:      "FileRemoveReq",
		FileWriteReqId:       "FileWriteReq",
		HeadRptId:            "HeadRpt",
		MarkReqId:            "MarkReq",
		MarkRptId:            "MarkRpt",
		MessageReqId:         "MessageReq",
		SessionLoginReqId:    "SessionLoginReq",
		SessionPauseReqId:    "SessionPauseReq",
		SessionQuitReqId:     "SessionQuitReq",
		SessionRedirectReqId: "SessionRedirectReq",
		SessionResumeReqId:   "SessionResumeReq",
		TraceReqId:           "TraceReq",
		UserAddReqId:         "UserAddReq",
		UserDelReqId:         "UserDelReq",
		UserSearchReqId:      "UserSearchReq",
		UserVouchReqId:       "UserVouchReq",

		SuccessId:      "Success",
		DeniedId:       "Denied",
		FailureId:      "Failure",
		IlFormatId:     "IlFormat",
		IncompatibleId: "Incompatible",
		RedirectId:     "Redirect",
		ShortId:        "Short",
		UnexpectedId:   "Unexpected",
		UnknownId:      "Unknown",
		UnsupportedId:  "Unsupported",

		RawId:     "Raw",
		TraceRxId: "TraceRx",
		TraceTxId: "TraceTx",
	}[i]
}

// Version returns the given version of an Id in byte form.
func (id Id) Version(version uint8) byte {
	if version > Version {
		version = Version
	}
	i := uint(version*MaxId) | uint(id)
	return [(Version + 1) * MaxId]byte{
		((0 * MaxId) | AckId):                ackV0,
		((0 * MaxId) | EchoId):               echoV0,
		((0 * MaxId) | FileLockReqId):        fileLockReqV0,
		((0 * MaxId) | FileReadReqId):        fileReadReqV0,
		((0 * MaxId) | FileRemoveReqId):      fileRemoveReqV0,
		((0 * MaxId) | FileWriteReqId):       fileWriteReqV0,
		((0 * MaxId) | HeadRptId):            headRptV0,
		((0 * MaxId) | MarkReqId):            markReqV0,
		((0 * MaxId) | MarkRptId):            markRptV0,
		((0 * MaxId) | MessageReqId):         messageReqV0,
		((0 * MaxId) | SessionLoginReqId):    sessionLoginReqV0,
		((0 * MaxId) | SessionPauseReqId):    sessionPauseReqV0,
		((0 * MaxId) | SessionQuitReqId):     sessionQuitReqV0,
		((0 * MaxId) | SessionRedirectReqId): sessionRedirectReqV0,
		((0 * MaxId) | SessionResumeReqId):   sessionResumeReqV0,
		((0 * MaxId) | TraceReqId):           traceReqV0,
		((0 * MaxId) | UserAddReqId):         userAddReqV0,
		((0 * MaxId) | UserDelReqId):         userDelReqV0,
		((0 * MaxId) | UserSearchReqId):      userSearchReqV0,
		((0 * MaxId) | UserVouchReqId):       userVouchReqV0,
	}[i]
}

// Header is an interface wrapper for the PDU header buffer.
type Header interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Len() int
	Next(int) []byte
}

// PDUer is an interface wrapper for each PDU type providing format, parse and
// trace methods.
type PDUer interface {
	Format(uint8, Header)
	Id() Id
	Parse(Header) Err
	String() string // format PDU as log friendly string
}

type Creator func() PDUer

var registration [NpduIds]Creator

// Register a creator for the given id.
func Register(id Id, creator Creator) {
	if id < NpduIds {
		registration[id] = creator
	}
}

// Create an empty PDU with the given id.
func New(id Id) PDUer {
	if id < NpduIds {
		if create := registration[id]; create != nil {
			return create()
		}
	}
	return nil
}

// Getc returns the next character (byte) read from the Header buffer.
func Getc(h Header) byte {
	buf := []byte{0}
	if n, err := h.Read(buf); err != nil && n != len(buf) {
		panic("short")
	}
	return buf[0]
}

// Ngets returns a string of the requested length read from the Header bufer.
func Ngets(h Header, n int) string {
	if n == 0 {
		return ""
	}
	sbuf := make([]byte, n)
	defer func() {
		sbuf = sbuf[:0]
		sbuf = nil
	}()
	if i, err := h.Read(sbuf); err != nil || i != n {
		return ""
	}
	return string(sbuf)
}
