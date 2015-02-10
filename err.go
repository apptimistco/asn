// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io"
	"strconv"
)

const (
	Success Err = iota
	DeniedErr
	FailureErr
	IlFormatErr
	IncompatibleErr
	RedirectErr
	ShortErr
	UnexpectedErr
	UnknownErr
	UnsupportedErr

	Nerrors

	MaxErr = 16
)

const (
	SuccessV0 Err = iota
	DeniedV0
	FailureV0
	IlFormatV0
	IncompatibleV0
	RedirectV0
	ShortV0
	UnexpectedV0
	UnknownV0
	UnsupportedV0
)

var (
	// These aren't Nack'd Err codes
	ErrDisestablished = errors.New("Disestablished session")
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

	ErrStrings = [Nerrors]string{
		Success:         "Success",
		DeniedErr:       "DeniedErr",
		FailureErr:      "FailureErr",
		IlFormatErr:     "IlFormatErr",
		IncompatibleErr: "IncompatibleErr",
		RedirectErr:     "RedirectErr",
		ShortErr:        "ShortErr",
		UnexpectedErr:   "UnexpectedErr",
		UnknownErr:      "UnknownErr",
		UnsupportedErr:  "UnsupportedErr",
	}

	Errors = [Nerrors]error{
		Success:         nil,
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

	VerErr = [(Latest + 1) * MaxErr]Err{
		((0 * MaxErr) | SuccessV0):      Success,
		((0 * MaxErr) | DeniedV0):       DeniedErr,
		((0 * MaxErr) | FailureV0):      FailureErr,
		((0 * MaxErr) | IlFormatV0):     IlFormatErr,
		((0 * MaxErr) | IncompatibleV0): IncompatibleErr,
		((0 * MaxErr) | RedirectV0):     RedirectErr,
		((0 * MaxErr) | ShortV0):        ShortErr,
		((0 * MaxErr) | UnexpectedV0):   UnexpectedErr,
		((0 * MaxErr) | UnknownV0):      UnknownErr,
		((0 * MaxErr) | UnsupportedV0):  UnsupportedErr,
	}

	ErrVer = [(Latest + 1) * MaxErr]Err{
		((0 * MaxErr) | Success):         SuccessV0,
		((0 * MaxErr) | DeniedErr):       DeniedV0,
		((0 * MaxErr) | FailureErr):      FailureV0,
		((0 * MaxErr) | IlFormatErr):     IlFormatV0,
		((0 * MaxErr) | IncompatibleErr): IncompatibleV0,
		((0 * MaxErr) | RedirectErr):     RedirectV0,
		((0 * MaxErr) | ShortErr):        ShortV0,
		((0 * MaxErr) | UnexpectedErr):   UnexpectedV0,
		((0 * MaxErr) | UnknownErr):      UnknownV0,
		((0 * MaxErr) | UnsupportedErr):  UnsupportedV0,
	}
)

type Err uint8

func ErrFromError(err error) (ecode Err) {
	ecode = FailureErr
	for i, e := range Errors {
		if e == err {
			ecode = Err(i)
			break
		}
	}
	return
}

// Internal Err from external Err of given version.
func (p *Err) Internal(v Version) {
	if v > Latest {
		*p = IncompatibleErr
	} else if i := int((uint8(v) * MaxErr) | uint8(*p)); i > int(Nerrors) {
		*p = UnknownErr
	} else {
		*p = VerErr[i]
	}
}

func (e Err) ErrToError() error {
	i := int(e)
	if i >= int(Nerrors) {
		return ErrUnknown
	}
	return Errors[i]
}

func (p *Err) ReadFrom(r io.Reader) (n int64, err error) {
	var b [1]byte
	ni, err := r.Read(b[:])
	if err == nil {
		n = int64(ni)
		*p = Err(b[0])
	}
	return
}

// Error and String return the name of internal Err.
func (e Err) Error() string { return e.String() }
func (e Err) String() string {
	err := e.ErrToError()
	if err == nil {
		return "Success"
	}
	return err.Error()
}

// Version returns the given version of an Err in byte form.
func (e Err) Version(v Version) Err {
	if v > Latest {
		v = Latest
	}
	i := int((int(v) * MaxErr) | int(e))
	return ErrVer[i]
}

func (e Err) WriteTo(w io.Writer) (n int64, err error) {
	b := []byte{byte(e)}
	ni, err := w.Write(b[:])
	if err == nil {
		n = int64(ni)
	}
	return
}

// Error records the name of the errant object and the reason it failed.
type Error struct{ name, reason string }

func (e *Error) Error() string {
	return "asn: " + strconv.Quote(e.name) + ": " + e.reason
}

// DescError prefaces a description to a given error
type DescError struct {
	desc string
	err  error
}

func (e *DescError) Error() string {
	return "asn: " + e.desc + ": " + e.err.Error()
}
