// Copyright 2014 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "encoding/binary"

var (
	SizeUint8  = binary.Size(uint8(0))
	SizeUint16 = binary.Size(uint16(0))
	SizeUint32 = binary.Size(uint32(0))
	SizeUint64 = binary.Size(uint64(0))
)
