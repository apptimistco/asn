// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build diag

package debug

import (
	"log"
	"log/syslog"
)

func init() {
	sl, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, tag())
	if err != nil {
		panic(err)
	}
	Diag = &Logger{log.New(sl, "", log.Lshortfile)}
}
