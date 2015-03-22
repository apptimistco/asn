// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build fixme

package debug

import (
	"log"
	"log/syslog"
)

func init() {
	sl, err := syslog.New(syslog.LOG_DEBUG|syslog.LOG_USER, tag())
	if err != nil {
		panic(err)
	}
	Fixme = &Logger{log.New(sl, "", log.Lshortfile)}
}
