// Copyright 2014-2015 Apptimist, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Copied from https://go.googlesource.com/go ... src/sync/mutex_test.go

package mutex

import (
	"sync"
	"testing"

	"github.com/apptimistco/asn/debug"
)

var (
	once sync.Once
	test struct {
		Mutex
	}
)

func setup() {
	test.Set("test")
	debug.Diag.Redirect("test.log")
}

func HammerMutex(loops int, cdone chan bool) {
	for i := 0; i < loops; i++ {
		test.Lock()
		test.Unlock()
	}
	cdone <- true
}

func TestMutex(t *testing.T) {
	once.Do(setup)
	c := make(chan bool)
	for i := 0; i < 10; i++ {
		go HammerMutex(1000, c)
	}
	for i := 0; i < 10; i++ {
		<-c
	}
}

func TestMutexPanic(t *testing.T) {
	once.Do(setup)
	defer func() {
		if recover() == nil {
			t.Fatalf("unlock of unlocked mutex did not panic")
		}
	}()

	test.Lock()
	test.Unlock()
	test.Unlock()
}
