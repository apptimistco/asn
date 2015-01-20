// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type Mode int

const (
	AdminMode Mode = iota
	ServerMode
)

func (m Mode) Admin() bool  { return m == AdminMode }
func (m Mode) Server() bool { return m == ServerMode }
