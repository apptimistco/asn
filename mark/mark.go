// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mark

import (
	"encoding/binary"
	"fmt"
	"github.com/apptimistco/asn/pdu"
	"github.com/apptimistco/encr"
	"math"
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
	Key encr.Pub

	Lat, Lon, Ele float64
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

func NewMarkRpt(key *encr.Pub, lat, lon, ele float64) *MarkRpt {
	return &MarkRpt{Key: *key, Lat: lat, Lon: lon, Ele: ele}
}

func (req *MarkReq) Format(version uint8) []byte {
	header := []byte{version, pdu.MarkReqId.Version(version)}
	for _, f := range [3]float64{req.Lat, req.Lon, req.Z} {
		bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(bytes, math.Float64bits(f))
		header = append(header, bytes...)
	}
	header = append(header, req.Cmd)
	return header
}

func (rsp *MarkRpt) Format(version uint8) []byte {
	header := []byte{version, pdu.MarkRptId.Version(version)}
	header = append(header, rsp.Key[:]...)
	for _, f := range [3]float64{rsp.Lat, rsp.Lon, rsp.Ele} {
		bytes := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(bytes, math.Float64bits(f))
		header = append(header, bytes...)
	}
	return header
}

func (req *MarkReq) Parse(header []byte) pdu.Err {
	i := 1 + 1
	if len(header) != i+(3*8)+1 {
		return pdu.IlFormatErr
	}
	for _, pf := range [3]*float64{&req.Lat, &req.Lon, &req.Z} {
		bits := binary.BigEndian.Uint64(header[i : i+8])
		*pf = math.Float64frombits(bits)
		i += 8
	}
	req.Cmd = header[i]
	return pdu.Success
}

func (rsp *MarkRpt) Parse(header []byte) pdu.Err {
	i := 1 + 1
	if len(header) != i+encr.PubSz+(3*8) {
		return pdu.IlFormatErr
	}
	copy(rsp.Key[:], header[i:i+encr.PubSz])
	i += encr.PubSz
	for _, pf := range [3]*float64{&rsp.Lat, &rsp.Lon, &rsp.Ele} {
		bits := binary.BigEndian.Uint64(header[i : i+8])
		*pf = math.Float64frombits(bits)
		i += 8
	}
	return pdu.Success
}

func (req *MarkReq) String(_ []byte) string {
	i := req.Cmd
	if i > Ncommands {
		i = Ncommands
	}
	return fmt.Sprintf("%s %f %f %f",
		[Ncommands + 1]string{Set: "Set",
			Unset:     "Unset",
			Checkin:   "Checkin",
			Checkout:  "Checkout",
			Scan:      "Scan",
			Stop:      "Stop",
			Ncommands: "invalid",
		}[i],
		req.Lat,
		req.Lon,
		req.Z)
}

func (rsp *MarkRpt) String(_ []byte) string {
	return fmt.Sprintf("%s... %f %f %f",
		rsp.Key.String()[:8],
		rsp.Lat,
		rsp.Lon,
		rsp.Ele)
}
