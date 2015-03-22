// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !nolog

package debug

import (
	"log"
	"log/syslog"
)

func init() {
	sl, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_USER, tag())
	if err != nil {
		panic(err)
	}
	Log = &Logger{log.New(sl, "", 0)}
}
