// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mark

import (
	"fmt"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/encr"
	"github.com/apptimistco/nbo"
)

const (
	Set uint8 = iota
	Unset
	Checkin
	Checkout
	Scan
	Stop
	Ncommands
)

type MarkReq struct {
	Lat float64 // Lat[itude] in degrees
	Lon float64 // Lon[gitude] in degrees
	Z   float64 // Elevation or Radius in meters
	Cmd uint8
}

type MarkRpt struct {
	Lat, Lon, Ele float64

	Key encr.Pub
}

func init() {
	pdu.Register(pdu.MarkReqId, func() pdu.PDUer {
		return &MarkReq{}
	})
	pdu.Register(pdu.MarkRptId, func() pdu.PDUer {
		return &MarkRpt{}
	})
}

func NewMarkReq(lat, lon, z float64, cmd uint8) *MarkReq {
	return &MarkReq{Lat: lat, Lon: lon, Z: z, Cmd: cmd}
}

func NewMarkRpt(lat, lon, ele float64, key *encr.Pub) *MarkRpt {
	return &MarkRpt{Key: *key, Lat: lat, Lon: lon, Ele: ele}
}

func (req *MarkReq) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.MarkReqId.Version(version)})
	(nbo.Writer{h}).WriteNBO(req.Lat)
	(nbo.Writer{h}).WriteNBO(req.Lon)
	(nbo.Writer{h}).WriteNBO(req.Z)
	(nbo.Writer{h}).WriteNBO(req.Cmd)
}

func (rpt *MarkRpt) Format(version uint8, h pdu.Header) {
	h.Write([]byte{version, pdu.MarkRptId.Version(version)})
	(nbo.Writer{h}).WriteNBO(rpt.Lat)
	(nbo.Writer{h}).WriteNBO(rpt.Lon)
	(nbo.Writer{h}).WriteNBO(rpt.Ele)
	h.Write(rpt.Key[:])
}

func (req *MarkReq) Id() pdu.Id { return pdu.MarkReqId }
func (req *MarkRpt) Id() pdu.Id { return pdu.MarkRptId }

func (req *MarkReq) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+(3*8)+1 {
		return pdu.IlFormatErr
	}
	h.Next(2)
	for _, pf := range []*float64{&req.Lat, &req.Lon, &req.Z} {
		if n, err := (nbo.Reader{h}).ReadNBO(pf); err != nil || n != 8 {
			return pdu.IlFormatErr
		}
	}
	if n, err := (nbo.Reader{h}).ReadNBO(&req.Cmd); err != nil || n != 1 {
		return pdu.IlFormatErr
	}
	return pdu.Success
}

func (rpt *MarkRpt) Parse(h pdu.Header) pdu.Err {
	if h.Len() != 1+1+encr.PubSz+(3*8) {
		return pdu.IlFormatErr
	}
	h.Next(2)
	for _, pf := range [3]*float64{&rpt.Lat, &rpt.Lon, &rpt.Ele} {
		if n, err := (nbo.Reader{h}).ReadNBO(pf); err != nil || n != 8 {
			return pdu.IlFormatErr
		}
	}
	if n, err := h.Read(rpt.Key[:]); err != nil || n != encr.PubSz {
		return pdu.IlFormatErr
	}
	return pdu.Success
}

func (req *MarkReq) String() string {
	i := req.Cmd
	if i > Ncommands {
		i = Ncommands
	}
	return fmt.Sprintf("%f %f %f %s",
		req.Lat,
		req.Lon,
		req.Z,
		[Ncommands + 1]string{Set: "Set",
			Unset:     "Unset",
			Checkin:   "Checkin",
			Checkout:  "Checkout",
			Scan:      "Scan",
			Stop:      "Stop",
			Ncommands: "invalid",
		}[i])
}

func (rsp *MarkRpt) String() string {
	return fmt.Sprintf("%f %f %f %s...",
		rsp.Lat,
		rsp.Lon,
		rsp.Ele,
		rsp.Key.String()[:8])
}
